package telegram

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"gatelock/internal/vault"
)

// By is where a denial in Telegram says it was given.
const By = "Telegram"

// The most of a reason, and of what a question asks, sent or kept, in
// runes. A message holds 4096. A question that names a command holds at
// most maxCommand of it, and maxAround of what comes before it and after.
const (
	maxReason   = 500
	maxQuestion = 3000
	maxCommand  = 2000
	maxAround   = 500
)

// maxHeld is the most of the user's answers kept while a message they
// may answer is being sent; past it, Telegram stops asking.
const maxHeld = 100

// errTooMany is no answer: the user sent more than maxHeld answers before
// the message they may answer was sent.
var errTooMany = errors.New("too many answers at once in Telegram to tell which is to the question")

// Approver asks the paired user, in their private chat with the bot.
type Approver struct {
	bot  *Bot
	user int64
	// host names the Mac asking, as the user may have several.
	host string
}

// NewApprover returns an approver asking user through bot, saying the
// Mac host asks.
func NewApprover(bot *Bot, user int64, host string) *Approver {
	return &Approver{bot: bot, user: user, host: host}
}

// The buttons' data: what was pressed, a colon, and the question's nonce.
const (
	pressApprove = "a"
	pressDeny    = "d"
	pressReason  = "r"
)

// Ask asks the user to approve what p.Reason says, as "unlock prod to run
// make deploy", with the command p.Command marks as a block of code. A
// question too long to send whole can only be denied, as the user cannot
// see what they would approve. It returns nil if they approve, a
// *vault.DeniedError if they deny, with what they said if they deny with a
// reason, ctx's error once ctx is done, which withdraws the question, or
// another error if the question could not be sent or answered.
func (a *Approver) Ask(ctx context.Context, p vault.Prompt) error {
	nonce := rand.Text()
	question, entities, whole := a.question(p)
	if !whole {
		question += "\n\nToo long to show here whole: approve it at the Mac, if you do."
	}
	answers := make(chan error, 1)
	give := func(err error) {
		select {
		case answers <- err:
		default:
		}
	}

	// All below with mu held.
	var mu sync.Mutex
	// asked is the question's message, once sent; prompt is the one asking
	// for a reason, -1 while being sent, and 0 before or if it fails. done
	// is set once answered, and verdict says how.
	var asked, prompt int64
	done, verdict := false, ""
	// held keeps the user's answers that may be to a message being sent,
	// to check once it is: Telegram may show it, and the user answer,
	// before replying to sendMessage. While any is held, the answers after
	// it are held too, so that they are taken in the order given.
	var held []update
	settle := func(text string, err error) {
		if done {
			return
		}
		done, verdict, held = true, text, nil
		if asked != 0 {
			a.bot.edit(a.user, asked, question+"\n\n"+verdict, entities)
		}
		give(err)
	}
	hold := func(u update) {
		if len(held) == maxHeld {
			settle("Too many answers at once to tell which is to this: answer at the Mac.", errTooMany)
			return
		}
		held = append(held, u)
	}
	var handle func(u update)
	// recheck checks the answers held again, once a message is sent.
	recheck := func() {
		again := held
		held = nil
		for _, u := range again {
			handle(u)
		}
	}
	// handle takes an update as an answer if it is one, holding it if it
	// may be to a message being sent.
	handle = func(u update) {
		if done {
			return
		}
		if q := u.CallbackQuery; q != nil {
			press, n, _ := strings.Cut(q.Data, ":")
			if n != nonce || q.Message == nil {
				return
			}
			if !a.mine(q.From, q.Message.Chat) {
				a.bot.answer(q.ID, "Only the user paired with Gatelock can answer.")
				return
			}
			if asked == 0 || len(held) > 0 {
				hold(u)
				return
			}
			if q.Message.MessageID != asked {
				return
			}
			switch press {
			case pressApprove:
				if !whole {
					return
				}
				a.bot.answer(q.ID, "Approved")
				settle("✅ Approved", nil)
			case pressDeny:
				a.bot.answer(q.ID, "Denied")
				settle("❌ Denied", &vault.DeniedError{By: By})
			case pressReason:
				a.bot.answer(q.ID, "")
				if prompt == 0 {
					prompt = -1
					go a.askReason(asked, func(id int64) {
						mu.Lock()
						defer mu.Unlock()
						prompt = id
						recheck()
					})
				}
			}
			return
		}
		// A reply to the question, or to the prompt for a reason, denies it
		// with that reason.
		m := u.Message
		if m == nil || m.From == nil || !a.mine(*m.From, m.Chat) || m.ReplyTo == nil {
			return
		}
		why := truncate(strings.TrimSpace(m.Text), maxReason)
		if why == "" {
			return
		}
		to := m.ReplyTo.MessageID
		answers := asked != 0 && to == asked || prompt > 0 && to == prompt
		switch {
		case answers && len(held) == 0:
			settle("❌ Denied: "+why, &vault.DeniedError{By: By, Reason: why})
		case answers || asked == 0 || prompt < 0:
			hold(u)
		}
	}
	// Subscribed before the question is sent, so that no answer is missed.
	cancel := a.bot.subscribe(func(u update) {
		mu.Lock()
		defer mu.Unlock()
		handle(u)
	})
	defer cancel()

	sent, err := a.bot.send(ctx, a.user, question, entities, keyboard(nonce, whole), 0)
	if err != nil {
		return err
	}
	mu.Lock()
	asked = sent.MessageID
	if done {
		a.bot.edit(a.user, asked, question+"\n\n"+verdict, entities)
	}
	recheck()
	mu.Unlock()

	select {
	case err := <-answers:
		return err
	case <-ctx.Done():
		mu.Lock()
		settle("No longer waiting.", ctx.Err())
		mu.Unlock()
		return ctx.Err()
	}
}

// question is the text of what Ask asks, and its entities: the reason in
// a sentence, or, when it names a command, the command in a block of code
// of its own, between what comes before it and after. whole is unset if
// what is asked had to be cut, other than the reason given after the
// command, which does not change what runs.
func (a *Approver) question(p vault.Prompt) (text string, entities []entity, whole bool) {
	text = "Gatelock on " + a.host + " wants to "
	c := p.Command
	if c[0] >= c[1] || c[1] > len(p.Reason) {
		text += p.Reason
		return truncate(text, maxQuestion) + ".", nil, utf8.RuneCountInString(text) <= maxQuestion
	}
	before, command := strings.TrimSpace(p.Reason[:c[0]]), p.Reason[c[0]:c[1]]
	whole = utf8.RuneCountInString(before) <= maxAround && utf8.RuneCountInString(command) <= maxCommand
	text += truncate(before, maxAround) + ":\n"
	command = truncate(command, maxCommand)
	code := entity{Type: "pre", Offset: utf16Len(text), Length: utf16Len(command)}
	text += command
	if after := strings.TrimSpace(p.Reason[c[1]:]); after != "" {
		text += "\n" + truncate(after, maxAround)
	}
	return text, []entity{code}, whole
}

// utf16Len is the length of s in UTF-16 code units, as Telegram counts.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// mine reports whether an answer came from the paired user, in their
// private chat with the bot, whose id is theirs.
func (a *Approver) mine(from User, in chat) bool {
	return from.ID == a.user && !from.IsBot && in.ID == a.user && in.Type == "private"
}

// askReason asks the user for the reason they deny the question asked, in
// a reply, and gives the message asking to sent, or 0 if it failed.
func (a *Approver) askReason(asked int64, sent func(int64)) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	m, err := a.bot.send(ctx, a.user, "Why deny it? Reply to this message; the agent sees your reason.", nil, map[string]any{
		"force_reply":             true,
		"input_field_placeholder": "Reason",
	}, asked)
	if err != nil {
		sent(0)
		return
	}
	sent(m.MessageID)
}

// keyboard is the question's buttons, with Approve only if approvable.
func keyboard(nonce string, approvable bool) any {
	button := func(text, press, style string) map[string]any {
		return map[string]any{"text": text, "callback_data": press + ":" + nonce, "style": style}
	}
	first := []any{button("Deny", pressDeny, "danger")}
	if approvable {
		first = append([]any{button("Approve", pressApprove, "success")}, first...)
	}
	return map[string]any{"inline_keyboard": [][]any{
		first,
		{button("Deny with a reason…", pressReason, "danger")},
	}}
}

// truncate cuts s to n runes, marking the cut.
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

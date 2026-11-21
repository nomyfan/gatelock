package telegram

import (
	"context"
	"crypto/rand"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"gatelock/internal/vault"
)

// By is where a denial in Telegram says it was given.
const By = "Telegram"

// The most of a reason, and of what a question asks, sent or kept, in
// runes. A message holds 4096.
const (
	maxReason   = 500
	maxQuestion = 3000
)

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

// Ask asks the user to approve what reason says, as "unlock prod to run
// make deploy". It returns nil if they approve, a *vault.DeniedError if
// they deny, with what they said if they deny with a reason, ctx's error
// once ctx is done, which withdraws the question, or another error if the
// question could not be sent.
func (a *Approver) Ask(ctx context.Context, reason string) error {
	nonce := rand.Text()
	question := truncate("Gatelock on "+a.host+" wants to "+reason, maxQuestion) + "."
	answers := make(chan error, 1)
	give := func(err error) {
		select {
		case answers <- err:
		default:
		}
	}

	var mu sync.Mutex
	// asked is the question's message, once sent; prompt is the one asking
	// for a reason, once sent; done is set once answered.
	var asked, prompt int64
	done := false
	settle := func(text string, err error) {
		// With mu held.
		if done {
			return
		}
		done = true
		a.bot.edit(a.user, asked, question+"\n\n"+text)
		give(err)
	}
	// Subscribed before the question is sent, so that no answer is missed.
	cancel := a.bot.subscribe(func(u update) {
		mu.Lock()
		defer mu.Unlock()
		if asked == 0 || done {
			return
		}
		if q := u.CallbackQuery; q != nil {
			press, n, _ := strings.Cut(q.Data, ":")
			if n != nonce || q.Message == nil || q.Message.MessageID != asked {
				return
			}
			if !a.mine(q.From, q.Message.Chat) {
				a.bot.answer(q.ID, "Only the user paired with Gatelock can answer.")
				return
			}
			switch press {
			case pressApprove:
				a.bot.answer(q.ID, "Approved")
				settle("✅ Approved", nil)
			case pressDeny:
				a.bot.answer(q.ID, "Denied")
				settle("❌ Denied", &vault.DeniedError{By: By})
			case pressReason:
				a.bot.answer(q.ID, "")
				if prompt == 0 {
					prompt = -1 // being sent
					go a.askReason(asked, func(id int64) {
						mu.Lock()
						defer mu.Unlock()
						prompt = id
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
		if to := m.ReplyTo.MessageID; to != asked && (prompt <= 0 || to != prompt) {
			return
		}
		why := truncate(strings.TrimSpace(m.Text), maxReason)
		if why == "" {
			return
		}
		settle("❌ Denied: "+why, &vault.DeniedError{By: By, Reason: why})
	})
	defer cancel()

	sent, err := a.bot.send(ctx, a.user, question, keyboard(nonce), 0)
	if err != nil {
		return err
	}
	mu.Lock()
	asked = sent.MessageID
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
	m, err := a.bot.send(ctx, a.user, "Why deny it? Reply to this message; the agent sees your reason.", map[string]any{
		"force_reply":             true,
		"input_field_placeholder": "Reason",
	}, asked)
	if err != nil {
		sent(0)
		return
	}
	sent(m.MessageID)
}

func keyboard(nonce string) any {
	button := func(text, press, style string) map[string]any {
		return map[string]any{"text": text, "callback_data": press + ":" + nonce, "style": style}
	}
	return map[string]any{"inline_keyboard": [][]any{
		{button("Approve", pressApprove, "success"), button("Deny", pressDeny, "danger")},
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

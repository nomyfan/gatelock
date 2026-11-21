// Package telegram asks the user to approve in a chat with a Telegram bot
// of their own, which they pair with Gatelock once.
//
// The bot is reached through the Bot API with long polling (getUpdates),
// so the Mac needs no address of its own; it polls only while it asks or
// pairs. A question has buttons to approve, deny, or deny with a reason,
// which the user then sends as a reply. Only the paired user's answers,
// in their private chat with the bot, count.
package telegram

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// defaultAPI is where the Bot API is; tests point a Bot elsewhere.
const defaultAPI = "https://api.telegram.org"

// pollTimeout is how long a getUpdates waits for an update.
var pollTimeout = 30 * time.Second

// tokenPattern is a bot token as BotFather gives it; it goes into URLs.
var tokenPattern = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)

// ErrWebhook is what Me fails with for a bot that delivers its updates to
// a webhook, as getUpdates does not work then.
var ErrWebhook = errors.New("the bot sends its updates to a webhook, so Gatelock cannot read them: use a bot of its own")

// Bot is a bot, by its token. It is safe from several goroutines.
type Bot struct {
	token string
	api   string
	hc    *http.Client

	mu   sync.Mutex
	subs map[int]func(update)
	next int
	// stop ends the poller running, if any; done is closed once the last
	// one has ended.
	stop   context.CancelFunc
	done   chan struct{}
	offset int64
}

// New returns the bot whose token BotFather gave.
func New(token string) (*Bot, error) {
	if !tokenPattern.MatchString(token) {
		return nil, errors.New("that is not a bot token: BotFather gives one like 123456:ABC-DEF…")
	}
	done := make(chan struct{})
	close(done)
	return &Bot{
		token: token,
		api:   defaultAPI,
		hc:    &http.Client{Timeout: pollTimeout + 15*time.Second},
		subs:  map[int]func(update){},
		done:  done,
	}, nil
}

// User is a Telegram user, or a bot.
type User struct {
	ID        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	Username  string `json:"username,omitempty"`
}

// Name is how the user is shown: their first name, and their username if
// they have one.
func (u User) Name() string {
	if u.Username == "" {
		return u.FirstName
	}
	if u.FirstName == "" {
		return "@" + u.Username
	}
	return u.FirstName + " (@" + u.Username + ")"
}

type chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

type message struct {
	MessageID int64    `json:"message_id"`
	From      *User    `json:"from"`
	Chat      chat     `json:"chat"`
	Text      string   `json:"text"`
	ReplyTo   *message `json:"reply_to_message"`
}

type callbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *message `json:"message"`
	Data    string   `json:"data"`
}

type update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *message       `json:"message"`
	CallbackQuery *callbackQuery `json:"callback_query"`
}

// APIError is the Bot API declining a call.
type APIError struct {
	Method      string
	Code        int
	Description string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("telegram %s: %s (%d)", e.Method, e.Description, e.Code)
}

// call calls a Bot API method with params as JSON, and decodes its result
// into result, if not nil. Its errors never hold the token, which is in
// the URL.
func (b *Bot) call(ctx context.Context, method string, params, result any) error {
	body, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.api+"/bot"+b.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("telegram %s: bad request", method)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	var r struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		ErrorCode   int             `json:"error_code"`
		Description string          `json:"description"`
	}
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("telegram %s: %s", method, resp.Status)
	}
	if !r.OK {
		return &APIError{Method: method, Code: r.ErrorCode, Description: r.Description}
	}
	if result == nil {
		return nil
	}
	if err := json.Unmarshal(r.Result, result); err != nil {
		return fmt.Errorf("telegram %s: %w", method, err)
	}
	return nil
}

// Me checks the token, and that the bot's updates can be polled, and
// returns the bot.
func (b *Bot) Me(ctx context.Context) (User, error) {
	var me User
	if err := b.call(ctx, "getMe", struct{}{}, &me); err != nil {
		return User{}, err
	}
	var hook struct {
		URL string `json:"url"`
	}
	if err := b.call(ctx, "getWebhookInfo", struct{}{}, &hook); err != nil {
		return User{}, err
	}
	if hook.URL != "" {
		return User{}, ErrWebhook
	}
	return me, nil
}

// send sends text to chat, with markup if not nil, and returns the message.
func (b *Bot) send(ctx context.Context, chat int64, text string, markup any, replyTo int64) (message, error) {
	params := map[string]any{"chat_id": chat, "text": text}
	if markup != nil {
		params["reply_markup"] = markup
	}
	if replyTo != 0 {
		params["reply_parameters"] = map[string]any{"message_id": replyTo, "allow_sending_without_reply": true}
	}
	var m message
	err := b.call(ctx, "sendMessage", params, &m)
	return m, err
}

// edit replaces a message's text, and takes its buttons away, in the
// background: failing leaves the message as it was, which is no harm.
func (b *Bot) edit(chat, id int64, text string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		b.call(ctx, "editMessageText", map[string]any{
			"chat_id":      chat,
			"message_id":   id,
			"text":         text,
			"reply_markup": map[string]any{"inline_keyboard": [][]any{}},
		}, nil)
	}()
}

// answer stops the spinner of a button, showing text if not empty, in the
// background.
func (b *Bot) answer(id, text string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		b.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text}, nil)
	}()
}

// subscribe calls fn with each update, on the poller's goroutine, until
// cancel is called; fn must not block. The bot polls while anyone is
// subscribed.
func (b *Bot) subscribe(fn func(update)) (cancel func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	id := b.next
	b.next++
	b.subs[id] = fn
	if b.stop == nil {
		ctx, stop := context.WithCancel(context.Background())
		prev, done := b.done, make(chan struct{})
		b.stop, b.done = stop, done
		go func() {
			defer close(done)
			// One getUpdates at a time, or Telegram ends the other.
			<-prev
			b.poll(ctx)
		}()
	}
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.subs, id)
		if len(b.subs) == 0 && b.stop != nil {
			b.stop()
			b.stop = nil
		}
	}
}

// poll gets updates until ctx is done, and hands each to the subscribers.
// An update is confirmed by the next getUpdates, so one canceled midway is
// got again.
func (b *Bot) poll(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		b.mu.Lock()
		offset := b.offset
		b.mu.Unlock()
		var updates []update
		err := b.call(ctx, "getUpdates", map[string]any{
			"offset":          offset,
			"timeout":         int(pollTimeout / time.Second),
			"allowed_updates": []string{"message", "callback_query"},
		}, &updates)
		if err != nil {
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			backoff = min(2*backoff, 30*time.Second)
			continue
		}
		backoff = time.Second
		for _, u := range updates {
			b.mu.Lock()
			b.offset = u.UpdateID + 1
			subs := make([]func(update), 0, len(b.subs))
			for _, fn := range b.subs {
				subs = append(subs, fn)
			}
			b.mu.Unlock()
			for _, fn := range subs {
				fn(u)
			}
		}
	}
}

// NewCode returns a code for pairing, to put in the bot's link.
func NewCode() string { return rand.Text() }

// Link is the link that opens a chat with the bot, whose Start button
// sends it /start code.
func Link(bot User, code string) string {
	return "https://t.me/" + url.PathEscape(bot.Username) + "?start=" + url.QueryEscape(code)
}

// Pair waits for someone to send the bot /start code in a private chat,
// as Link has them do, and returns them, once it has told them they are
// paired.
func (b *Bot) Pair(ctx context.Context, code string) (User, error) {
	paired := make(chan message, 1)
	cancel := b.subscribe(func(u update) {
		m := u.Message
		if m == nil || m.From == nil || m.From.IsBot || m.Chat.Type != "private" || m.Text != "/start "+code {
			return
		}
		select {
		case paired <- *m:
		default:
		}
	})
	defer cancel()
	select {
	case m := <-paired:
		if _, err := b.send(ctx, m.Chat.ID, "Paired with Gatelock. It will ask you here before a command may use a vault that allows it.", nil, 0); err != nil {
			return User{}, err
		}
		return *m.From, nil
	case <-ctx.Done():
		return User{}, ctx.Err()
	}
}

// Config is the bot paired, and the user it asks, as kept on disk; the
// token is kept apart, in the Keychain.
type Config struct {
	Bot  User `json:"bot"`
	User User `json:"user"`
}

// LoadConfig reads the config kept at path; none is os.ErrNotExist.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, err
	}
	if c.User.ID == 0 {
		return Config{}, errors.New("no user paired")
	}
	return c, nil
}

// Save writes the config to path, all at once.
func (c Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gatelock/internal/vault"
)

const (
	token = "123456:secret-token_ABC"
	user  = int64(4242)
)

// fakeAPI is the Bot API, as far as Gatelock uses it.
type fakeAPI struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	webhook string
	updates []update
	nextID  int64
	nextMsg int64
	calls   []call
}

type call struct {
	method string
	params map[string]any
}

func newFake(t *testing.T) (*fakeAPI, *Bot) {
	t.Helper()
	f := &fakeAPI{t: t, nextMsg: 100}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	b, err := New(token)
	if err != nil {
		t.Fatal(err)
	}
	b.api = f.srv.URL
	return f, b
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	method, ok := strings.CutPrefix(r.URL.Path, "/bot"+token+"/")
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{"ok": false, "error_code": 404, "description": "Not Found"})
		return
	}
	var params map[string]any
	json.NewDecoder(r.Body).Decode(&params)
	reply := func(result any) { json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result}) }
	if method == "getUpdates" {
		offset := int64(params["offset"].(float64))
		for deadline := time.Now().Add(100 * time.Millisecond); ; time.Sleep(5 * time.Millisecond) {
			f.mu.Lock()
			f.calls = append(f.calls, call{method, params})
			var out []update
			for _, u := range f.updates {
				if u.UpdateID >= offset {
					out = append(out, u)
				}
			}
			f.mu.Unlock()
			if len(out) > 0 || time.Now().After(deadline) || r.Context().Err() != nil {
				reply(out)
				return
			}
		}
	}
	f.mu.Lock()
	f.calls = append(f.calls, call{method, params})
	f.mu.Unlock()
	switch method {
	case "getMe":
		reply(User{ID: 1, IsBot: true, FirstName: "Gatelock", Username: "my_gatelock_bot"})
	case "getWebhookInfo":
		f.mu.Lock()
		defer f.mu.Unlock()
		reply(map[string]any{"url": f.webhook})
	case "sendMessage":
		f.mu.Lock()
		f.nextMsg++
		id := f.nextMsg
		f.mu.Unlock()
		chatID := int64(params["chat_id"].(float64))
		reply(message{MessageID: id, Chat: chat{ID: chatID, Type: "private"}, Text: params["text"].(string)})
	default:
		reply(true)
	}
}

func (f *fakeAPI) push(u update) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	u.UpdateID = f.nextID
	f.updates = append(f.updates, u)
}

// waitCall waits for the nth call (from 1) of method that match accepts,
// and returns its params.
func (f *fakeAPI) waitCall(method string, match func(map[string]any) bool) map[string]any {
	f.t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		f.mu.Lock()
		for _, c := range f.calls {
			if c.method == method && (match == nil || match(c.params)) {
				f.mu.Unlock()
				return c.params
			}
		}
		f.mu.Unlock()
	}
	f.t.Fatalf("no %s call", method)
	return nil
}

func (f *fakeAPI) count(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.method == method {
			n++
		}
	}
	return n
}

var me = User{ID: user, FirstName: "Ada", Username: "ada"}

func privateChat() chat { return chat{ID: user, Type: "private"} }

// asking starts asking, and returns the question's message id, the data
// of its buttons by press, and the answer to come.
func asking(t *testing.T, f *fakeAPI, b *Bot, ctx context.Context) (int64, map[string]string, chan error) {
	t.Helper()
	answer := make(chan error, 1)
	go func() {
		answer <- NewApprover(b, user, "Ada's MacBook").Ask(ctx, vault.Prompt{Reason: "unlock prod for Claude Code to run make deploy", Command: [2]int{35, 46}})
	}()
	p := f.waitCall("sendMessage", nil)
	if int64(p["chat_id"].(float64)) != user {
		t.Fatalf("asked chat %v", p["chat_id"])
	}
	if text := p["text"].(string); text != "Gatelock on Ada's MacBook wants to unlock prod for Claude Code to run:\nmake deploy" {
		t.Fatalf("asked %q", text)
	}
	if e := fmt.Sprint(p["entities"]); e != "[map[length:11 offset:71 type:pre]]" {
		t.Fatalf("entities %s", e)
	}
	data := map[string]string{}
	for _, row := range p["reply_markup"].(map[string]any)["inline_keyboard"].([]any) {
		for _, b := range row.([]any) {
			d := b.(map[string]any)["callback_data"].(string)
			if len(d) > 64 {
				t.Fatalf("callback data of %d bytes", len(d))
			}
			press, _, _ := strings.Cut(d, ":")
			data[press] = d
		}
	}
	f.mu.Lock()
	id := f.nextMsg
	f.mu.Unlock()
	return id, data, answer
}

func press(f *fakeAPI, from User, asked int64, data string) {
	f.push(update{CallbackQuery: &callbackQuery{ID: "q" + data, From: from, Data: data, Message: &message{MessageID: asked, Chat: privateChat()}}})
}

func wait(t *testing.T, answer chan error) error {
	t.Helper()
	select {
	case err := <-answer:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
		return nil
	}
}

func edited(f *fakeAPI, asked int64, text string) map[string]any {
	return f.waitCall("editMessageText", func(p map[string]any) bool {
		return int64(p["message_id"].(float64)) == asked && strings.HasSuffix(p["text"].(string), text)
	})
}

func TestApprove(t *testing.T) {
	f, b := newFake(t)
	asked, data, answer := asking(t, f, b, context.Background())
	press(f, me, asked, data[pressApprove])
	if err := wait(t, answer); err != nil {
		t.Fatalf("got %v", err)
	}
	p := edited(f, asked, "\n\n✅ Approved")
	if p["entities"] == nil {
		t.Fatal("the command no longer marked once answered")
	}
	if kb := p["reply_markup"].(map[string]any)["inline_keyboard"].([]any); len(kb) != 0 {
		t.Fatal("buttons left on the question")
	}
	f.waitCall("answerCallbackQuery", nil)

	// Once nothing asks, the bot stops polling.
	time.Sleep(300 * time.Millisecond)
	n := f.count("getUpdates")
	time.Sleep(300 * time.Millisecond)
	if f.count("getUpdates") != n {
		t.Fatal("still polling with nothing asked")
	}
}

func TestDeny(t *testing.T) {
	f, b := newFake(t)
	asked, data, answer := asking(t, f, b, context.Background())
	press(f, me, asked, data[pressDeny])
	var denied *vault.DeniedError
	if err := wait(t, answer); !errors.As(err, &denied) || denied.By != "Telegram" || denied.Reason != "" {
		t.Fatalf("got %v", err)
	}
	edited(f, asked, "\n\n❌ Denied")
}

func TestDenyWithReason(t *testing.T) {
	f, b := newFake(t)
	asked, data, answer := asking(t, f, b, context.Background())
	press(f, me, asked, data[pressReason])
	p := f.waitCall("sendMessage", func(p map[string]any) bool { return p["reply_markup"].(map[string]any)["force_reply"] == true })
	if int64(p["reply_parameters"].(map[string]any)["message_id"].(float64)) != asked {
		t.Fatal("the prompt for a reason does not reply to the question")
	}
	f.mu.Lock()
	prompt := f.nextMsg
	f.mu.Unlock()
	// Pressing it again asks once.
	press(f, me, asked, data[pressReason])
	f.push(update{Message: &message{MessageID: 900, From: &me, Chat: privateChat(), Text: "  use staging, not prod ", ReplyTo: &message{MessageID: prompt}}})
	var denied *vault.DeniedError
	if err := wait(t, answer); !errors.As(err, &denied) || denied.By != "Telegram" || denied.Reason != "use staging, not prod" {
		t.Fatalf("got %v", err)
	}
	edited(f, asked, "\n\n❌ Denied: use staging, not prod")
	if n := f.count("sendMessage"); n != 2 {
		t.Fatalf("%d messages sent", n)
	}
}

func TestReplyToTheQuestionDenies(t *testing.T) {
	f, b := newFake(t)
	asked, _, answer := asking(t, f, b, context.Background())
	f.push(update{Message: &message{MessageID: 900, From: &me, Chat: privateChat(), Text: "not now", ReplyTo: &message{MessageID: asked}}})
	var denied *vault.DeniedError
	if err := wait(t, answer); !errors.As(err, &denied) || denied.Reason != "not now" {
		t.Fatalf("got %v", err)
	}
}

func TestOnlyThePairedUserAnswers(t *testing.T) {
	f, b := newFake(t)
	asked, data, answer := asking(t, f, b, context.Background())
	stranger := User{ID: 7, FirstName: "Eve"}
	press(f, stranger, asked, data[pressApprove])
	// A bot passing for the user.
	press(f, User{ID: user, IsBot: true, FirstName: "Bot"}, asked, data[pressApprove])
	// A button of another question.
	press(f, me, asked, pressApprove+":"+"OTHERNONCE")
	// The user, replying in a group the bot is in.
	f.push(update{Message: &message{MessageID: 900, From: &me, Chat: chat{ID: -100, Type: "group"}, Text: "ok", ReplyTo: &message{MessageID: asked}}})
	// A reply to another message.
	f.push(update{Message: &message{MessageID: 901, From: &me, Chat: privateChat(), Text: "hm", ReplyTo: &message{MessageID: asked - 1}}})
	f.waitCall("answerCallbackQuery", func(p map[string]any) bool { return strings.HasPrefix(p["text"].(string), "Only") })
	time.Sleep(100 * time.Millisecond)
	select {
	case err := <-answer:
		t.Fatalf("answered %v", err)
	default:
	}
	press(f, me, asked, data[pressDeny])
	if err := wait(t, answer); !errors.Is(err, vault.ErrDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestWithdrawn(t *testing.T) {
	f, b := newFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	asked, data, answer := asking(t, f, b, ctx)
	cancel()
	if err := wait(t, answer); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	edited(f, asked, "\n\nNo longer waiting.")
	// A press after is no answer, and edits nothing more.
	press(f, me, asked, data[pressApprove])
	time.Sleep(100 * time.Millisecond)
	if n := f.count("editMessageText"); n != 1 {
		t.Fatalf("%d edits", n)
	}
}

func TestSendFailing(t *testing.T) {
	f, b := newFake(t)
	b.api = f.srv.URL + "/gone"
	err := NewApprover(b, user, "Mac").Ask(context.Background(), vault.Prompt{Reason: "unlock prod"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || errors.Is(err, vault.ErrDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestPair(t *testing.T) {
	f, b := newFake(t)
	got := make(chan User, 1)
	errs := make(chan error, 1)
	go func() {
		u, err := b.Pair(context.Background(), "CODE1")
		got <- u
		errs <- err
	}()
	stranger := User{ID: 7, FirstName: "Eve"}
	f.push(update{Message: &message{MessageID: 1, From: &stranger, Chat: chat{ID: 7, Type: "private"}, Text: "/start WRONG"}})
	f.push(update{Message: &message{MessageID: 2, From: &User{ID: 8, IsBot: true}, Chat: chat{ID: 8, Type: "private"}, Text: "/start CODE1"}})
	f.push(update{Message: &message{MessageID: 3, From: &me, Chat: chat{ID: -100, Type: "group"}, Text: "/start CODE1"}})
	f.push(update{Message: &message{MessageID: 4, From: &me, Chat: privateChat(), Text: "/start CODE1"}})
	select {
	case u := <-got:
		if err := <-errs; err != nil || u.ID != user {
			t.Fatalf("paired %+v, %v", u, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not paired")
	}
	if p := f.waitCall("sendMessage", nil); int64(p["chat_id"].(float64)) != user {
		t.Fatalf("told %v", p["chat_id"])
	}
}

func TestMe(t *testing.T) {
	f, b := newFake(t)
	bot, err := b.Me(context.Background())
	if err != nil || bot.Username != "my_gatelock_bot" {
		t.Fatalf("got %+v, %v", bot, err)
	}
	if link := Link(bot, "CODE1"); link != "https://t.me/my_gatelock_bot?start=CODE1" {
		t.Fatalf("link %s", link)
	}
	f.mu.Lock()
	f.webhook = "https://example.com/hook"
	f.mu.Unlock()
	if _, err := b.Me(context.Background()); !errors.Is(err, ErrWebhook) {
		t.Fatalf("with a webhook: %v", err)
	}
}

func TestErrorsNeverHoldTheToken(t *testing.T) {
	f, b := newFake(t)
	f.srv.Close()
	_, err := b.Me(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("got %v", err)
	}
}

func TestNewChecksTheToken(t *testing.T) {
	for _, bad := range []string{"", "abc", "123:abc/../x", "123:abc def", "123:abc?x=1"} {
		if _, err := New(bad); err == nil {
			t.Errorf("%q taken", bad)
		}
	}
}

func TestConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "telegram.json")
	c := Config{Bot: User{ID: 1, IsBot: true, Username: "my_gatelock_bot"}, User: me}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil || got != c {
		t.Fatalf("got %+v, %v", got, err)
	}
	if me.Name() != "Ada (@ada)" {
		t.Fatalf("name %q", me.Name())
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("héllo wörld", 5); got != "héll…" {
		t.Fatalf("got %q", got)
	}
}

func TestQuestion(t *testing.T) {
	a := NewApprover(nil, user, "Ada's 💻")
	for _, c := range []struct {
		reason  string
		command [2]int
		text    string
		code    *entity
	}{
		{"show the values", [2]int{}, "Gatelock on Ada's 💻 wants to show the values.", nil},
		{"unlock prod to run make deploy", [2]int{19, 30}, "Gatelock on Ada's 💻 wants to unlock prod to run:\nmake deploy", &entity{"pre", 50, 11}},
		// UTF-16 counts 🔐 and 💻 as two each.
		{`unlock 🔐 to run echo "é 🔐" (reason given: "check it")`, [2]int{19, 33}, "Gatelock on Ada's 💻 wants to unlock 🔐 to run:\necho \"é 🔐\"\n(reason given: \"check it\")", &entity{"pre", 48, 11}},
	} {
		text, entities := a.question(vault.Prompt{Reason: c.reason, Command: c.command})
		if text != c.text {
			t.Errorf("%q: asked %q", c.reason, text)
		}
		if c.code == nil && entities != nil || c.code != nil && (len(entities) != 1 || entities[0] != *c.code) {
			t.Errorf("%q: entities %+v", c.reason, entities)
		}
	}
}

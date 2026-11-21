package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"gatelock/internal/approve"
	"gatelock/internal/macauth"
	"gatelock/internal/telegram"
	"gatelock/internal/vault"
)

// tokenAccount is the Keychain account of the bot's token. The vaults'
// accounts are their ids, from rand.Text, which this cannot be.
const tokenAccount = "telegram-bot-token"

// remote is the Telegram pairing, used by the goroutines that ask as well
// as the main thread. The bot and the user are kept in telegram.json, the
// token in the Keychain, read once Telegram is first asked.
type remote struct {
	path string
	kc   vault.Keychain

	mu       sync.Mutex
	config   *telegram.Config // nil while not paired
	approver *telegram.Approver
}

// load reads the pairing kept, if any.
func (r *remote) load() {
	c, err := telegram.LoadConfig(r.path)
	if err != nil {
		return
	}
	r.mu.Lock()
	r.config = &c
	r.mu.Unlock()
}

// paired returns the pairing, and whether there is one.
func (r *remote) paired() (telegram.Config, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.config == nil {
		return telegram.Config{}, false
	}
	return *r.config, true
}

// ask asks the paired user in Telegram, as telegram.Approver.Ask does.
func (r *remote) ask(ctx context.Context, reason string) error {
	r.mu.Lock()
	if r.config == nil {
		r.mu.Unlock()
		return errors.New("Telegram is not set up")
	}
	ap := r.approver
	user := r.config.User.ID
	r.mu.Unlock()
	if ap == nil {
		token, err := r.kc.Get(tokenAccount)
		if err != nil {
			return errors.New("the Telegram bot's token is not in the Keychain: set Telegram up again")
		}
		bot, err := telegram.New(string(token))
		if err != nil {
			return err
		}
		ap = telegram.NewApprover(bot, user, computerName())
		r.mu.Lock()
		if r.config != nil && r.config.User.ID == user && r.approver == nil {
			r.approver = ap
		}
		r.mu.Unlock()
	}
	return ap.Ask(ctx, reason)
}

// pair keeps the pairing of user with bot, whose token it is.
func (r *remote) pair(bot *telegram.Bot, token string, c telegram.Config) error {
	if err := r.kc.Set(tokenAccount, []byte(token)); err != nil {
		return err
	}
	if err := c.Save(r.path); err != nil {
		r.kc.Delete(tokenAccount)
		return err
	}
	r.mu.Lock()
	r.config = &c
	r.approver = telegram.NewApprover(bot, c.User.ID, computerName())
	r.mu.Unlock()
	return nil
}

// forget removes the pairing, and the token.
func (r *remote) forget() error {
	if err := os.Remove(r.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	r.mu.Lock()
	r.config, r.approver = nil, nil
	r.mu.Unlock()
	return r.kc.Delete(tokenAccount)
}

// computerName is the Mac's name as the user knows it, which a question
// names, as they may have several.
func computerName() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "scutil", "--get", "ComputerName").Output(); err == nil {
		if name := strings.TrimSpace(string(out)); name != "" {
			return name
		}
	}
	name, _ := os.Hostname()
	return strings.TrimSuffix(name, ".local")
}

// ConfirmUser asks with Touch ID or the login password, and, when the
// vault allows it and Telegram is set up, in Telegram as well, taking the
// first answer; app is the vault's Authorizer.
func (a *app) ConfirmUser(ctx context.Context, p vault.Prompt) error {
	if _, ok := a.remote.paired(); !p.Remote || !ok {
		return macauth.ConfirmUser(ctx, p.Reason)
	}
	return approve.First(ctx, func(ctx context.Context) error {
		err := macauth.ConfirmUser(ctx, p.Reason)
		if errors.Is(err, macauth.ErrSystemCancel) {
			// No answer: the user may be away, and answer in Telegram.
			return errors.New("Touch ID was " + macauth.ErrSystemCancel.Error())
		}
		return err
	}, func(ctx context.Context) error {
		return a.remote.ask(ctx, p.Reason)
	})
}

// telegramSetup is the Setup page's Telegram card's.
type telegramSetup struct {
	token string
	busy  bool
	// link opens the bot's chat, where the user presses Start to pair,
	// while pairing; cancel stops pairing.
	link   string
	cancel context.CancelFunc
}

// connectTelegram checks the token typed, then waits for the user to pair
// in the bot's chat, for ten minutes at most.
func (a *app) connectTelegram() {
	s := &a.view.setup.telegram
	token := strings.TrimSpace(s.token)
	bot, err := telegram.New(token)
	if err != nil {
		a.view.toast = err.Error()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	s.busy, s.cancel = true, cancel
	go func() {
		defer cancel()
		check, done := context.WithTimeout(ctx, 15*time.Second)
		me, err := bot.Me(check)
		done()
		var user telegram.User
		if err == nil {
			code := telegram.NewCode()
			link := telegram.Link(me, code)
			mygo.RunOnMain(func() {
				s.link = link
				a.refresh()
			})
			if user, err = bot.Pair(ctx, code); err == nil {
				err = a.remote.pair(bot, token, telegram.Config{Bot: me, User: user})
			}
		}
		mygo.RunOnMain(func() {
			s.busy, s.link, s.cancel = false, "", nil
			switch {
			case errors.Is(err, context.Canceled):
			case errors.Is(err, context.DeadlineExceeded):
				a.view.toast = "Not paired: no one pressed Start in time"
			case err != nil:
				a.view.toast = err.Error()
			default:
				s.token = ""
				a.view.toast = "Paired with " + user.Name()
			}
			a.refresh()
		})
	}()
}

func (a *app) telegramCard(c *ui.Context) {
	t := c.Theme()
	s := &a.view.setup.telegram
	config, paired := a.remote.paired()
	card(c, func() {
		ui.Row(c).AlignItems(ui.Center).Gap(t.Space(4)).Padding(t.Space(2.5), 0).Children(func() {
			ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(0.5)).Children(func() {
				ui.Text(c, "Telegram").FontWeight(600)
				about := "Approve or deny commands from your phone, with a reason the agent sees, for the vaults that allow it. Make a bot of Gatelock's own with @BotFather, and paste its token here."
				switch {
				case paired:
					about = "Asks " + config.User.Name() + " through @" + config.Bot.Username + ", for the vaults that allow it in their settings."
				case s.link != "":
					about = "Open the bot's chat on the account that will approve, and press Start."
				}
				ui.Text(c, about).FontSize(t.FontSize - 1).TextColor(t.TextMuted).Wrap()
			})
			switch {
			case paired:
				if ui.Button(c, "Disconnect").Clicked() {
					if err := a.remote.forget(); err != nil {
						a.view.toast = err.Error()
					}
				}
			case s.busy:
				if ui.Button(c, "Cancel").Clicked() && s.cancel != nil {
					s.cancel()
				}
			}
		})
		if paired {
			return
		}
		divider(c)
		if s.link != "" {
			ui.Row(c).AlignItems(ui.Center).Gap(t.Space(2)).Padding(t.Space(2.5), 0).Children(func() {
				ui.Text(c, s.link).Font("monospace").FontSize(t.FontSize - 1).Selectable().Grow(1).MinWidth(0).SingleLine()
				if primaryButton(c, "Open Chat").Clicked() {
					c.OpenURL(s.link)
				}
			})
			return
		}
		ui.Row(c).AlignItems(ui.Center).Gap(t.Space(2)).Padding(t.Space(2.5), 0).Children(func() {
			input := ui.TextInput(c.Key("telegram-token"), &s.token).Password().Placeholder("Bot token").Label("Bot token").Grow(1).Disabled(s.busy)
			connect := primaryButton(c, "Connect").Disabled(s.busy || strings.TrimSpace(s.token) == "")
			if (connect.Clicked() || input.Submitted()) && !s.busy && strings.TrimSpace(s.token) != "" {
				a.connectTelegram()
			}
		})
	})
}

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
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

// tokenAccount begins the Keychain account of a pairing's bot token, which
// the rest, from rand.Text, makes its own, so that pairings in other data
// directories keep theirs. The vaults' accounts are their ids, from
// rand.Text alone, which these cannot be.
const tokenAccount = "telegram-bot-token-"

// newTokenAccount returns a Keychain account for a new pairing's token.
func newTokenAccount() string { return tokenAccount + rand.Text() }

// ownTokenAccount reports whether account is one newTokenAccount returns,
// as a pairing read from disk must have, so that disconnecting cannot
// delete another item, such as a vault's passphrase.
func ownTokenAccount(account string) bool {
	rest, ok := strings.CutPrefix(account, tokenAccount)
	// rand.Text gives 26 now, and may give more later.
	return ok && len(rest) >= 26 && strings.Trim(rest, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") == ""
}

// remote is the Telegram pairing, used by the goroutines that ask as well
// as the main thread. The bot and the user are kept in telegram.json, the
// token in the Keychain, read once Telegram is first asked.
type remote struct {
	path string
	kc   vault.Keychain
	rt   http.RoundTripper // the bots', http.DefaultTransport if nil

	mu       sync.Mutex
	config   *telegram.Config // nil while not paired
	approver *telegram.Approver
	// pairing is done once the pairing is gone, which withdraws what it
	// asks; nil while not paired.
	pairing context.Context
	unpair  context.CancelFunc
}

// set makes c, asked through ap if not nil, the pairing, ending the one
// before; with r.mu held.
func (r *remote) set(c *telegram.Config, ap *telegram.Approver) {
	if r.unpair != nil {
		r.unpair()
	}
	r.config, r.approver, r.pairing, r.unpair = c, ap, nil, nil
	if c != nil {
		r.pairing, r.unpair = context.WithCancel(context.Background())
	}
}

// load reads the pairing kept, if any. One without a token account of
// its own is none, and is paired again.
func (r *remote) load() {
	c, err := telegram.LoadConfig(r.path)
	if err != nil || !ownTokenAccount(c.TokenAccount) {
		return
	}
	r.mu.Lock()
	r.set(&c, nil)
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

// errUnpaired is what asking returns once the pairing is gone.
var errUnpaired = errors.New("Telegram is not set up")

// ask asks the paired user in Telegram, as telegram.Approver.Ask does.
// Disconnecting withdraws the question, and an answer got after counts
// for nothing.
func (r *remote) ask(ctx context.Context, p vault.Prompt) error {
	r.mu.Lock()
	if r.config == nil {
		r.mu.Unlock()
		return errUnpaired
	}
	ap, config, pairing := r.approver, *r.config, r.pairing
	r.mu.Unlock()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(pairing, cancel)()
	if ap == nil {
		token, err := r.kc.Get(config.TokenAccount)
		if err != nil {
			return errors.New("the Telegram bot's token is not in the Keychain: set Telegram up again")
		}
		bot, err := telegram.New(string(token), r.rt)
		if err != nil {
			return err
		}
		ap = telegram.NewApprover(bot, config.User.ID, computerName())
		r.mu.Lock()
		if r.pairing == pairing && r.approver == nil {
			r.approver = ap
		}
		r.mu.Unlock()
	}
	err := ap.Ask(ctx, p)
	if pairing.Err() != nil {
		return errUnpaired
	}
	return err
}

// pair keeps the pairing of user with bot, whose token it is, under a
// Keychain account of its own.
func (r *remote) pair(bot *telegram.Bot, token string, c telegram.Config) error {
	c.TokenAccount = newTokenAccount()
	if err := r.kc.Set(c.TokenAccount, []byte(token)); err != nil {
		return err
	}
	if err := c.Save(r.path); err != nil {
		r.kc.Delete(c.TokenAccount)
		return err
	}
	ap := telegram.NewApprover(bot, c.User.ID, computerName())
	r.mu.Lock()
	r.set(&c, ap)
	r.mu.Unlock()
	return nil
}

// forget removes the pairing: it withdraws what the pairing asks, then
// removes the token, then the pairing kept. If either fails, the pairing
// stays, so that disconnecting again finishes it.
func (r *remote) forget() error {
	r.mu.Lock()
	c := r.config
	r.set(nil, nil)
	r.mu.Unlock()
	if c == nil {
		return nil
	}
	err := r.kc.Delete(c.TokenAccount)
	if err == nil {
		if err = os.Remove(r.path); errors.Is(err, os.ErrNotExist) {
			err = nil
		}
	}
	if err != nil {
		r.mu.Lock()
		if r.config == nil {
			r.set(c, nil)
		}
		r.mu.Unlock()
	}
	return err
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
		return a.remote.ask(ctx, p)
	})
}

// telegramSetup is the Setup page's Telegram card's.
type telegramSetup struct {
	token string
	busy  bool
	// proxy is the proxy typed, the one set until changed.
	proxy string
	reach reachState
	// link opens the bot's chat, where the user presses Start to pair,
	// while pairing; cancel stops pairing.
	link   string
	cancel context.CancelFunc
}

// reachState is what checking that Telegram can be reached found.
type reachState struct {
	checked  bool // a check was started
	checking bool
	route    string // as proxy.route says, when the check began
	took     time.Duration
	err      error
	// gen tells a check's result from an older one's; cancel drops the
	// check under way.
	gen    int
	cancel context.CancelFunc
}

// checkReach checks, in the background, that Telegram can be reached as
// it is now, dropping the check under way, if any. It checks only while
// paired, so that the app does not reach out to Telegram for a user who
// does not use it; unpaired, it clears what an earlier check found.
func (a *app) checkReach() {
	r := &a.view.setup.telegram.reach
	if r.cancel != nil {
		r.cancel()
	}
	gen := r.gen + 1
	*r = reachState{gen: gen}
	if _, paired := a.remote.paired(); !paired || a.reach == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	*r = reachState{checked: true, checking: true, route: a.proxy.route(), gen: gen, cancel: cancel}
	go func() {
		defer cancel()
		start := time.Now()
		err := a.reach(ctx)
		took := time.Since(start)
		if errors.Is(ctx.Err(), context.Canceled) {
			return // dropped
		}
		if errors.Is(err, context.DeadlineExceeded) {
			err = errors.New("no answer in 15 seconds")
		}
		mygo.RunOnMain(func() { a.reached(gen, took, err) })
	}()
}

// reached shows what the check gen found, unless another was started
// since.
func (a *app) reached(gen int, took time.Duration, err error) {
	r := &a.view.setup.telegram.reach
	if r.gen != gen {
		return
	}
	r.checking, r.took, r.err, r.cancel = false, took, err, nil
	if a.win != nil {
		a.win.Invalidate()
	}
}

// reachLine is the card's line saying whether Telegram can be reached.
func (a *app) reachLine(c *ui.Context) {
	t := c.Theme()
	r := &a.view.setup.telegram.reach
	if !r.checked {
		return
	}
	text, color := "Checking that Telegram can be reached "+r.route+"…", t.TextMuted
	switch {
	case r.checking:
	case r.err != nil:
		text, color = "Telegram can't be reached "+r.route+": "+r.err.Error(), t.Danger
	default:
		text, color = "Telegram is reachable "+r.route+", in "+r.took.Round(time.Millisecond).String(), t.Success
	}
	ui.Text(c, text).FontSize(t.FontSize - 1).TextColor(color).Wrap()
}

// unreachable is the error of checking a bot's token: one that is not
// the Bot API's answer, nor canceling, says Telegram could not be
// reached, and is not wrapped, as the check timing out is not pairing
// doing so.
func unreachable(err error) error {
	var api *telegram.APIError
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, telegram.ErrWebhook) || errors.As(err, &api) {
		return err
	}
	return errors.New("Could not reach Telegram (" + err.Error() + "). If it is blocked on this network, set a proxy below.")
}

// connectTelegram checks the token typed, then waits for the user to pair
// in the bot's chat, for ten minutes at most.
func (a *app) connectTelegram() {
	s := &a.view.setup.telegram
	token := strings.TrimSpace(s.token)
	bot, err := telegram.New(token, a.remote.rt)
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
		err = unreachable(err)
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
		mygo.RunOnMain(func() { a.connected(user, err) })
	}()
}

// connected shows how connecting ended: paired with user, unless err.
func (a *app) connected(user telegram.User, err error) {
	s := &a.view.setup.telegram
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
		a.checkReach()
	}
	a.refresh()
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
					} else {
						a.checkReach()
					}
				}
			case s.busy:
				if ui.Button(c, "Cancel").Clicked() && s.cancel != nil {
					s.cancel()
				}
			}
		})
		switch {
		case paired:
		case s.link != "":
			divider(c)
			ui.Row(c).AlignItems(ui.Center).Gap(t.Space(2)).Padding(t.Space(2.5), 0).Children(func() {
				ui.Text(c, s.link).Font("monospace").FontSize(t.FontSize - 1).Selectable().Grow(1).MinWidth(0).SingleLine()
				if primaryButton(c, "Open Chat").Clicked() {
					c.OpenURL(s.link)
				}
			})
		default:
			divider(c)
			ui.Row(c).AlignItems(ui.Center).Gap(t.Space(2)).Padding(t.Space(2.5), 0).Children(func() {
				input := ui.TextInput(c.Key("telegram-token"), &s.token).Password().Placeholder("Bot token").Label("Bot token").Grow(1).Disabled(s.busy)
				connect := primaryButton(c, "Connect").Disabled(s.busy || strings.TrimSpace(s.token) == "")
				if (connect.Clicked() || input.Submitted()) && !s.busy && strings.TrimSpace(s.token) != "" {
					a.connectTelegram()
				}
			})
		}
		divider(c)
		ui.Column(c).Gap(t.Space(1)).Padding(t.Space(2.5), 0).Children(func() {
			ui.Row(c).AlignItems(ui.Center).Gap(t.Space(2)).Children(func() {
				changed := strings.TrimSpace(s.proxy) != a.proxy.String()
				input := ui.TextInput(c.Key("telegram-proxy"), &s.proxy).Placeholder("Proxy, such as http://127.0.0.1:7890").Label("Proxy").Grow(1)
				save := ui.Button(c, "Save").Disabled(!changed)
				if (save.Clicked() || input.Submitted()) && changed {
					a.setProxy()
				}
			})
			a.reachLine(c)
			ui.Text(c, "Telegram is reached through this proxy, else through HTTPS_PROXY if the app has it, else directly. The proxy looks up Telegram's address, so a Mac whose DNS gives a wrong one still reaches it.").
				FontSize(t.FontSize - 1).TextColor(t.TextMuted).Wrap()
		})
	})
}

// setProxy keeps the proxy typed as the one Telegram is reached through.
func (a *app) setProxy() {
	s := &a.view.setup.telegram
	if err := a.proxy.set(s.proxy); err != nil {
		a.view.toast = err.Error()
		return
	}
	s.proxy = a.proxy.String()
	a.checkReach()
	if s.proxy == "" {
		a.view.toast = "Proxy removed"
	} else {
		a.view.toast = "Proxy saved"
	}
}

package main

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"gatelock/internal/history"
	"gatelock/internal/ipc"
	"gatelock/internal/macauth"
	"gatelock/internal/vault"
)

// app is the running app: the vaults, the record of activities, and the
// state its windows show, which the main thread owns.
type app struct {
	home    string
	vaults  *vault.Store
	history *history.Store

	win      *mygo.Window // the main window, nil while closed
	tray     *mygo.Tray
	quitting bool
	// dirty is set as the vaults or the activities change, for the next
	// refresh.
	dirty atomic.Bool
	// expiry refreshes as the first unlock with a TTL ends, at expiresAt,
	// which changes nothing the store would report.
	expiry    *time.Timer
	expiresAt time.Time

	view viewState
}

func runApp() {
	if !mygo.App.RequestSingleInstanceLock() {
		return
	}
	dir, err := home()
	if err != nil {
		log.Fatal(err)
	}
	a := &app{home: dir}
	if a.vaults, err = vault.Open(filepath.Join(dir, "vaults"), keychain{}, a); err != nil {
		log.Fatal(err)
	}
	if a.history, err = history.Open(filepath.Join(dir, "activities"), func() { a.dirty.Store(true) }); err != nil {
		log.Fatal(err)
	}
	l, err := ipc.Listen(socketPath(dir))
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := ipc.Serve(l, a.vaults, a.history); err != nil {
			log.Println("serve:", err)
		}
	}()
	a.view.page = pageActivities
	a.refresh()

	mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
	// The app lives in the menu bar: closing its windows leaves it running.
	mygo.App.OnWindowAllClosed(func() {})
	mygo.App.OnSecondInstance(func(args []string, _ string) {
		if !slices.Contains(args, "--background") {
			a.openWindow()
		}
	})
	mygo.App.OnBeforeQuit(a.beforeQuit)
	mygo.App.WhenReady(func() {
		a.makeTray()
		if !slices.Contains(os.Args, "--background") {
			a.openWindow()
		}
		go a.refreshLoop()
	})
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}

// openWindow shows the main window, making it if it is closed.
func (a *app) openWindow() {
	mygo.App.SetActivationPolicy(mygo.ActivationPolicyRegular)
	if a.win == nil {
		a.win = mygo.NewWindow(mygo.WindowOptions{
			Title:     "Gatelock",
			Width:     960,
			Height:    640,
			MinWidth:  720,
			MinHeight: 420,
			StateKey:  "main",
			// The window controls sit over the sidebar, centered on the
			// pages' headers.
			TitleBarStyle:        mygo.TitleBarHidden,
			TrafficLightPosition: &mygo.Point{X: 18, Y: titleBand/2 - 8},
			Content:              ui.View(a.mainView),
		})
		a.win.OnClose(func(*mygo.CloseEvent) {
			a.win = nil
			mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
		})
	}
	a.win.Show()
	a.win.Focus()
	mygo.App.Focus()
}

// beforeQuit asks before stopping the commands running, then stops them,
// so that their records say so, and quits.
func (a *app) beforeQuit(e *mygo.QuitEvent) {
	if a.quitting || a.history.Running() == 0 {
		return
	}
	e.PreventDefault()
	go func() {
		n := a.history.Running()
		res, err := mygo.Dialog.Message(mygo.MessageOptions{
			Type:    mygo.MessageWarning,
			Message: fmt.Sprintf("Quit Gatelock and stop %s?", plural(n, "running command", "running commands")),
			Detail:  "Commands run through gatelock stop when the app quits.",
			Buttons: []string{"Quit", "Cancel"},
		})
		if err != nil || res.Button != 0 {
			return
		}
		a.history.StopAll()
		for deadline := time.Now().Add(7 * time.Second); a.history.Running() > 0 && time.Now().Before(deadline); {
			time.Sleep(100 * time.Millisecond)
		}
		mygo.RunOnMain(func() { a.quitting = true })
		mygo.App.Quit()
	}()
}

// refreshLoop picks up changes to the vaults and the activities, at most
// ten times a second, as output may come far more often. While any activity
// has yet to end, it also builds the window again each second, for how long
// each has taken, which nothing else would report.
func (a *app) refreshLoop() {
	var last time.Time
	for now := range time.Tick(100 * time.Millisecond) {
		if a.dirty.Swap(false) {
			last = now
			mygo.RunOnMain(a.refresh)
		} else if now.Sub(last) >= time.Second && a.history.Running() > 0 {
			last = now
			mygo.RunOnMain(func() {
				if a.win != nil {
					a.win.Invalidate()
				}
			})
		}
	}
}

// refresh reads the vaults and the activities anew, on the main thread.
func (a *app) refresh() {
	v := &a.view
	v.vaults = a.vaults.Vaults()
	var next time.Time
	for _, vt := range v.vaults {
		// Locked, by its TTL or otherwise, the vault's values shown hide,
		// as with Lock Now. Under Every it is never kept unlocked.
		if vt.Name == v.revealedVault && v.revealed != nil && !vt.Unlocked && vt.Policy.Mode != vault.Every {
			a.hideValues()
		}
		if vt.Unlocked && !vt.Expires.IsZero() && (next.IsZero() || vt.Expires.Before(next)) {
			next = vt.Expires
		}
	}
	if !next.Equal(a.expiresAt) {
		if a.expiry != nil {
			a.expiry.Stop()
		}
		a.expiry, a.expiresAt = nil, next
		if !next.IsZero() {
			a.expiry = time.AfterFunc(time.Until(next), func() { a.dirty.Store(true) })
		}
	}
	v.activities = a.history.List()
	running := a.history.Running()
	if running != v.running && a.tray != nil {
		a.tray.SetTitle(trayTitle(running))
	}
	v.running = running
	for id, rv := range v.activityViews {
		if !rv.open {
			continue
		}
		if out, err := a.history.Output(id); err == nil {
			rv.output = tail(string(out), 200<<10)
		}
	}
	if a.win != nil {
		a.win.Invalidate()
	}
}

func trayTitle(running int) string {
	if running == 0 {
		return ""
	}
	return fmt.Sprint(running)
}

func (a *app) makeTray() {
	tray, err := mygo.NewTray(mygo.TrayOptions{
		ID:             "gatelock",
		Icon:           trayIcon,
		IconIsTemplate: true,
		ToolTip:        "Gatelock",
		Menu: mygo.NewMenu([]*mygo.MenuItem{
			{Label: "Open Gatelock", Click: func(*mygo.MenuItem, *mygo.Window) { a.openWindow() }},
			{Label: "Lock All Vaults", Click: func(*mygo.MenuItem, *mygo.Window) {
				a.lock("")
				a.refresh()
			}},
			mygo.Separator(),
			{Role: mygo.RoleQuit},
		}),
	})
	if err != nil {
		log.Println("tray:", err)
		return
	}
	a.tray = tray
	tray.SetTitle(trayTitle(a.view.running))
}

// trayIcon is the hedgehog of the app icon as a silhouette, black on clear,
// for macOS to tint; scripts/make-tray-icon.sh renders it from design/.
//
//go:embed icons/tray.png
var trayIcon []byte

// keychain keeps passphrases in the login Keychain, under the app's
// identifier.
type keychain struct{}

func (keychain) Get(account string) ([]byte, error)      { return mygo.Secrets.Get(account) }
func (keychain) Set(account string, secret []byte) error { return mygo.Secrets.Set(account, secret) }
func (keychain) Delete(account string) error {
	if err := mygo.Secrets.Delete(account); err != nil && !errors.Is(err, mygo.ErrSecretNotFound) {
		return err
	}
	return nil
}

// ConfirmUser asks with Touch ID or the login password; app is the vault's
// Authorizer.
func (a *app) ConfirmUser(ctx context.Context, reason string) error {
	return macauth.ConfirmUser(ctx, reason)
}

// AskPassphrase asks in a window of its own, in front of the others.
func (a *app) AskPassphrase(ctx context.Context, name, reason string, retry bool) ([]byte, error) {
	p := &passphrasePrompt{vault: name, reason: reason, retry: retry, answer: make(chan []byte, 1)}
	var win *mygo.Window
	mygo.RunOnMain(func() {
		win = mygo.NewWindow(mygo.WindowOptions{
			Title:           "Unlock " + name,
			Width:           440,
			Height:          230,
			DisableResize:   true,
			DisableMinimize: true,
			AlwaysOnTop:     true,
			Content:         ui.View(p.view),
		})
		win.OnClose(func(*mygo.CloseEvent) { p.give(nil) })
		win.Focus()
		mygo.App.Focus()
	})
	defer mygo.RunOnMain(win.Close)
	select {
	case passphrase := <-p.answer:
		if passphrase == nil {
			return nil, vault.ErrDenied
		}
		return passphrase, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// passphrasePrompt asks for a vault's passphrase.
type passphrasePrompt struct {
	vault, reason string
	retry         bool
	value         string
	answer        chan []byte // nil for no
}

// give answers, once.
func (p *passphrasePrompt) give(passphrase []byte) {
	select {
	case p.answer <- passphrase:
	default:
	}
}

func (p *passphrasePrompt) view(c *ui.Context) {
	setTheme(c)
	t := c.Theme()
	if c.Shortcut(0, ui.KeyEscape) {
		p.give(nil)
	}
	ui.Column(c).Fill().Padding(t.Space(5)).Gap(t.Space(3)).Background(t.Background).Children(func() {
		ui.Row(c).Gap(t.Space(2)).AlignItems(ui.Center).Children(func() {
			ui.Icon(c, lockIcon).Size(18, 18).TextColor(t.Accent)
			ui.Text(c, "Unlock "+p.vault).FontSize(t.FontSize + 3).Bold()
		})
		ui.Text(c, "Gatelock wants to "+p.reason+".").TextColor(t.TextMuted).Wrap()
		input := ui.TextInput(c.Key("passphrase"), &p.value).Password().Placeholder("Passphrase").AutoFocus().Label("Passphrase")
		if p.retry {
			ui.Text(c, "That passphrase is wrong.").FontSize(t.FontSize - 1).TextColor(t.Danger)
		}
		ui.Row(c).Gap(t.Space(2)).Justify(ui.End).Grow(1).AlignItems(ui.End).Children(func() {
			if ui.Button(c, "Cancel").Clicked() {
				p.give(nil)
			}
			unlock := primaryButton(c, "Unlock").Disabled(p.value == "")
			if (unlock.Clicked() || input.Submitted()) && p.value != "" {
				p.give([]byte(p.value))
			}
		})
	})
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// tail returns the last n bytes of s, from a line's start.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[len(s)-n:]
	if i := bytes.IndexByte([]byte(s), '\n'); i >= 0 {
		s = s[i+1:]
	}
	return "…\n" + s
}

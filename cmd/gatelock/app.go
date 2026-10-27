package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
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

// app is the running app: the vault, the record of runs, and the state
// its windows show, which the main thread owns.
type app struct {
	home    string
	vault   *vault.Vault
	history *history.Store

	win      *mygo.Window // the main window, nil while closed
	tray     *mygo.Tray
	quitting bool
	// dirty is set as the vault or the runs change, for the next refresh.
	dirty atomic.Bool

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
	if a.vault, err = vault.Open(filepath.Join(dir, "namespaces"), keychain{}, a); err != nil {
		log.Fatal(err)
	}
	if a.history, err = history.Open(filepath.Join(dir, "runs"), func() { a.dirty.Store(true) }); err != nil {
		log.Fatal(err)
	}
	l, err := ipc.Listen(socketPath(dir))
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := ipc.Serve(l, a.vault, a.history); err != nil {
			log.Println("serve:", err)
		}
	}()
	a.view.page = pageRuns
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
			// As Mux: the window controls sit over the sidebar, centered on
			// the pages' headers.
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

// refreshLoop picks up changes to the vault and the runs, at most ten
// times a second, as output may come far more often.
func (a *app) refreshLoop() {
	for range time.Tick(100 * time.Millisecond) {
		if a.dirty.Swap(false) {
			mygo.RunOnMain(a.refresh)
		}
	}
}

// refresh reads the vault and the runs anew, on the main thread.
func (a *app) refresh() {
	v := &a.view
	v.namespaces = a.vault.Namespaces()
	v.runs = a.history.List()
	running := a.history.Running()
	if running != v.running && a.tray != nil {
		a.tray.SetTitle(trayTitle(running))
	}
	v.running = running
	for id, rv := range v.runViews {
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
		Icon:           trayIcon(),
		IconIsTemplate: true,
		ToolTip:        "Gatelock",
		Menu: mygo.NewMenu([]*mygo.MenuItem{
			{Label: "Open Gatelock", Click: func(*mygo.MenuItem, *mygo.Window) { a.openWindow() }},
			{Label: "Lock All Namespaces", Click: func(*mygo.MenuItem, *mygo.Window) {
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

// trayIcon draws a padlock, black on clear, for macOS to tint.
func trayIcon() []byte {
	const size = 36
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	ink := color.NRGBA{A: 255}
	for y := range size {
		for x := range size {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			// The body.
			body := fx >= 8 && fx <= 28 && fy >= 16 && fy <= 32
			// The shackle: a ring's upper half and its legs down to the body.
			d := math.Hypot(fx-18, fy-12)
			shackle := fy <= 12 && d >= 5 && d <= 8.5
			legs := fy > 12 && fy < 17 && ((fx >= 9.5 && fx <= 13) || (fx >= 23 && fx <= 26.5))
			// The keyhole is left clear.
			hole := math.Hypot(fx-18, fy-22) <= 2.2 || (fx >= 17 && fx <= 19 && fy >= 22 && fy <= 27)
			if (body || shackle || legs) && !hole {
				img.Set(x, y, ink)
			}
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

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
func (a *app) AskPassphrase(ctx context.Context, ns, reason string, retry bool) ([]byte, error) {
	p := &passphrasePrompt{namespace: ns, reason: reason, retry: retry, answer: make(chan []byte, 1)}
	var win *mygo.Window
	mygo.RunOnMain(func() {
		win = mygo.NewWindow(mygo.WindowOptions{
			Title:           "Unlock " + ns,
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

// passphrasePrompt asks for a namespace's passphrase.
type passphrasePrompt struct {
	namespace, reason string
	retry             bool
	value             string
	answer            chan []byte // nil for no
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
			ui.Text(c, "Unlock "+p.namespace).FontSize(t.FontSize + 3).Bold()
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

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/ui"

	"gatelock/internal/history"
	"gatelock/internal/vault"
)

// The pages of the main window besides the namespaces', whose ids are
// nsPage of their names.
const (
	pageRuns  = "runs"
	pageSetup = "setup"
)

func nsPage(name string) string { return "ns/" + name }

// viewState is what the main window shows, beyond the vault and the runs.
type viewState struct {
	page       string
	namespaces []vault.Namespace
	runs       []history.Run
	running    int
	// runViews are the runs the user has opened on the runs page, by id.
	runViews map[string]*runView
	toast    string // shown in the next frame

	sidebarHidden bool
	// headerInset is how far the pages' headers keep from the left.
	headerInset float32

	// The namespace page: the values shown, of revealedNS. revealGen
	// changes as they are hidden, so that a reveal under way then shows
	// nothing.
	revealed   map[string]string
	revealedNS string
	revealGen  int
	// form is the row of the env list being typed in, if any.
	form envForm
	// deleteKey is to be deleted once the user confirms, while deleting.
	deleteKey string
	deleting  bool
	// imported lists the keys of importedFrom, a .env file the user may
	// remove now, while askRemove.
	imported     []string
	importedFrom string
	askRemove    bool

	creating   bool
	create     createForm
	nsSettings bool
	settings   settingsForm
	// deleteNS is to be deleted once the user confirms, while deletingNS.
	deleteNS   string
	deletingNS bool

	setup setupState
}

// policies are the choices of how long an authorization lasts, as a
// segmented control shows them.
var policies = []vault.PolicyMode{vault.Every, vault.TTL, vault.Session}

var ttls = []struct {
	label string
	d     time.Duration
}{{"5 minutes", 5 * time.Minute}, {"15 minutes", 15 * time.Minute}, {"1 hour", time.Hour}, {"8 hours", 8 * time.Hour}}

func ttlLabels() []string {
	var out []string
	for _, t := range ttls {
		out = append(out, t.label)
	}
	return out
}

func policyOf(mode int, ttl string) vault.Policy {
	p := vault.Policy{Mode: policies[mode]}
	if p.Mode == vault.TTL {
		p.TTL = ttls[1].d
		for _, t := range ttls {
			if t.label == ttl {
				p.TTL = t.d
			}
		}
	}
	return p
}

func describePolicy(p vault.Policy) string {
	switch p.Mode {
	case vault.TTL:
		for _, t := range ttls {
			if t.d == p.TTL {
				return "Asks once every " + t.label
			}
		}
		return "Asks once every " + p.TTL.String()
	case vault.Session:
		return "Asks once until Gatelock quits"
	}
	return "Asks every time"
}

func (a *app) mainView(c *ui.Context) {
	setTheme(c)
	t := c.Theme()
	v := &a.view
	if v.toast != "" {
		c.Toast(v.toast)
		v.toast = ""
	}
	if c.Shortcut(ui.Cmd, ui.KeyB) {
		v.sidebarHidden = !v.sidebarHidden
	}
	bar := c.TitleBar()
	row := ui.Row(c).Fill().AlignItems(ui.Stretch).Background(t.Background)
	shown := row.Animate("sidebar", b2f(!v.sidebarHidden), 250*time.Millisecond)
	row.Children(func() {
		// The sidebar slides out to the left as it hides.
		w := sidebarWidth * shown
		ui.Row(c).Width(w).Shrink(0).AlignItems(ui.Stretch).Clip().Children(func() {
			ui.Column(c).Width(sidebarWidth).Shrink(0).Margin(0, 0, 0, w-sidebarWidth).Background(t.Surface).
				Children(func() { a.sidebar(c) })
		})
		if w > 0 {
			ui.Box(c).Width(1).Shrink(0).Background(t.Border)
		}
		// Hidden, the sidebar leaves the headers' room for the window
		// controls and the toggle.
		v.headerInset = t.Space(5) + (1-shown)*(bar.Left+36)
		ui.Column(c.Key(v.page)).Grow(1).MinWidth(0).Children(func() {
			switch {
			case v.page == pageSetup:
				a.setupPage(c)
			case strings.HasPrefix(v.page, "ns/"):
				a.namespacePage(c, strings.TrimPrefix(v.page, "ns/"))
			default:
				a.runsPage(c)
			}
		})
	})
	label := "Hide Sidebar"
	if v.sidebarHidden {
		label = "Show Sidebar"
	}
	// Beside the window controls, where it stays as the sidebar hides.
	if iconButton(c, "sidebar", sidebarIcon, label).Absolute().Left(bar.Left + 8).Top((titleBand - 26) / 2).Clicked() {
		v.sidebarHidden = !v.sidebarHidden
	}
	a.createDialog(c)
	a.deleteDialog(c)
}

const sidebarWidth = 220

func b2f(b bool) float32 {
	if b {
		return 1
	}
	return 0
}

// titleBand is the height of the band along the top that the window
// controls sit in, the sidebar's top and the pages' headers.
const titleBand = 44

func (a *app) sidebar(c *ui.Context) {
	t := c.Theme()
	v := &a.view
	ui.Box(c).Height(titleBand).Shrink(0).DragWindow()
	ui.Sidebar(c, &v.page, func() {
		item(c, pageRuns, runsIcon, "Activities", v.page, func(bool) {
			if v.running > 0 {
				ui.Text(c, fmt.Sprint(v.running)).FontSize(t.FontSize - 1).TextColor(t.Accent).FontWeight(600)
			}
		})
		item(c, pageSetup, setupIcon, "Setup", v.page, nil)
		ui.Row(c.Key("namespaces")).Height(28).AlignItems(ui.Center).Padding(0, t.Space(1), 0, t.Space(2)).
			Margin(t.Space(3), 0, 0, 0).Shrink(0).Children(func() {
			ui.Text(c, "Vaults").FontSize(t.FontSize - 1).FontWeight(600).TextColor(t.TextMuted).Grow(1)
			if iconButton(c, "new", plusIcon, "New Vault").Clicked() {
				v.create = createForm{keychain: true, ttl: ttls[1].label}
				v.creating = true
			}
		})
		for _, ns := range v.namespaces {
			item(c.Key(ns.Name), nsPage(ns.Name), lockIcon, ns.Name, v.page, func(hovered bool) {
				// Shown while hovered, so as not to crowd the list, and over
				// the item, which it would otherwise make taller.
				if !hovered {
					return
				}
				ui.Box(c).Absolute().Right(t.Space(1)).Top(0).Bottom(0).Center().Children(func() {
					if iconButton(c, "delete", trashIcon, "Delete "+ns.Name+"…").Clicked() {
						v.deleteNS, v.deletingNS = ns.Name, true
					}
				})
			})
		}
		if len(v.namespaces) == 0 {
			ui.Text(c, "None yet").FontSize(t.FontSize-1).TextColor(t.TextMuted).Padding(t.Space(1), t.Space(2))
		}
	}).Grow(1).Label("Pages").Padding(0, t.Space(2))
}

// item is a sidebar item, chosen as Mux shows it: on a darker ground
// rather than the accent, with what trailing builds after its label,
// told whether the item is hovered. Its icon is drawn
// over a blank one, in the accent, since SidebarItem tints its own for the
// accent ground.
func item(c *ui.Context, id string, icon *ui.SVG, label, chosen string, trailing func(hovered bool)) {
	t := c.Theme()
	// Tall enough for an iconButton, with room around it.
	e := ui.SidebarItem(c, id, blankIcon, label).Height(32)
	if id == chosen {
		e.Background(t.SurfacePressed).TextColor(t.Text)
	}
	e.Children(func() {
		ui.Box(c).Absolute().Left(t.Space(2)).Top(0).Bottom(0).Center().Children(func() {
			ui.Icon(c, icon).Size(16, 16).TextColor(t.Accent)
		})
		if trailing != nil {
			trailing(e.Hovered())
		}
	})
}

// header heads a page along the window's top, as Mux heads its panes:
// the page's icon and title, what it is about, and its actions at the
// right. It drags the window as a title bar would.
func (a *app) header(c *ui.Context, icon *ui.SVG, title, subtitle string, actions func()) {
	t := c.Theme()
	ui.Row(c).Height(titleBand).Shrink(0).AlignItems(ui.Stretch).Gap(t.Space(2)).Padding(0, t.Space(3), 0, 0).Children(func() {
		// The actions stay out of what drags the window, which would take
		// their clicks.
		ui.Row(c).Grow(1).MinWidth(0).AlignItems(ui.Center).Gap(t.Space(2)).Padding(0, 0, 0, a.view.headerInset).DragWindow().Children(func() {
			ui.Icon(c, icon).Size(15, 15).TextColor(t.Accent)
			ui.Text(c, title).Bold().SingleLine().Shrink(0)
			if subtitle != "" {
				ui.Text(c, subtitle).TextColor(t.TextMuted).SingleLine().Shrink(1).MinWidth(0)
			}
		})
		if actions != nil {
			ui.Row(c).AlignItems(ui.Center).Gap(t.Space(2)).Shrink(0).Children(actions)
		}
	})
}

func card(c *ui.Context, fn func()) {
	t := c.Theme()
	ui.Column(c).Shrink(0).Padding(t.Space(1), t.Space(4)).Border(1, t.Border).Radius(t.Space(2)).Children(fn)
}

// background runs fn off the main thread, then done with its error on it.
func (a *app) background(fn func() error, done func(error)) {
	go func() {
		err := fn()
		mygo.RunOnMain(func() {
			done(err)
			a.refresh()
		})
	}()
}

// report shows err, unless it is the user declining.
func (a *app) report(err error) {
	if err != nil && !errors.Is(err, vault.ErrDenied) {
		a.view.toast = err.Error()
	}
}

// --- Namespaces ---

func (a *app) namespacePage(c *ui.Context, name string) {
	t := c.Theme()
	v := &a.view
	var ns vault.Namespace
	found := false
	for _, n := range v.namespaces {
		if n.Name == name {
			ns, found = n, true
		}
	}
	if !found {
		v.page = pageRuns
		return
	}
	if v.revealedNS != name {
		v.revealed, v.revealedNS = nil, name
	}
	keychain := "passphrase typed each time"
	if ns.Keychain {
		keychain = "passphrase in the Keychain"
	}
	a.header(c, lockIcon, ns.Name, describePolicy(ns.Policy)+", "+keychain, func() {
		if iconButton(c, "add", plusIcon, "Add Env…").Clicked() {
			v.form = envForm{open: true, mask: true}
		}
		label, ic := "Show Values", eyeIcon
		if v.revealed != nil {
			label, ic = "Hide Values", eyeOffIcon
		}
		if iconButton(c, "reveal", ic, label).Clicked() {
			if v.revealed != nil {
				a.hideValues()
			} else {
				a.reveal(name)
			}
		}
		if iconButton(c, "lock", lockIcon, "Lock Now").Clicked() {
			a.lock(name)
			v.toast = name + " is locked"
		}
		if iconButton(c, "import", importIcon, "Import .env…").Clicked() {
			a.importDotenv(name)
		}
		if iconButton(c, "export", exportIcon, "Export .env…").Clicked() {
			a.exportDotenv(name)
		}
		if iconButton(c, "settings", settingsIcon, "Settings").Clicked() {
			v.settings = settingsFormOf(ns)
			v.nsSettings = true
		}
	})
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).Padding(t.Space(1), t.Space(5), t.Space(5), t.Space(5)).Gap(t.Space(4)).Children(func() {
			card(c, func() {
				adding := v.form.open && !v.form.editing
				if len(ns.Envs) == 0 && !adding {
					ui.Text(c, "No env yet. Add one with +, or import a .env file.").TextColor(t.TextMuted).Padding(t.Space(3), 0)
				}
				for i, e := range ns.Envs {
					if i > 0 {
						ui.Divider(c)
					}
					if v.form.open && v.form.editing && v.form.key == e.Key {
						a.envFormRow(c, name)
					} else {
						a.envRow(c, name, e)
					}
				}
				if adding {
					if len(ns.Envs) > 0 {
						ui.Divider(c)
					}
					a.envFormRow(c, name)
				}
			})
			ui.Text(c, "Run a command with these env:").TextColor(t.TextMuted).FontSize(t.FontSize - 1)
			ui.Text(c, "gatelock run "+name+" -- <command> [args...]").Font("monospace").Selectable().
				Padding(t.Space(2), t.Space(3)).Background(t.Surface).Radius(t.Space(1.5))
		})
	})
	a.envDialogs(c, name)
	a.settingsDialog(c, ns)
}

func (a *app) envRow(c *ui.Context, ns string, e vault.Env) {
	t := c.Theme()
	v := &a.view
	ui.Row(c.Key(e.Key)).AlignItems(ui.Center).Gap(t.Space(3)).Padding(t.Space(2), 0).Children(func() {
		ui.Text(c, e.Key).Font("monospace").Bold().Width(220).Shrink(0).SingleLine().Tooltip(e.Key)
		value, shown := v.revealed[e.Key]
		if shown {
			ui.Text(c, value).Font("monospace").Selectable().Grow(1).MinWidth(0).SingleLine().Tooltip(value)
		} else {
			ui.Text(c, "••••••••").TextColor(t.TextMuted).Grow(1)
		}
		if shown && e.Sensitive && len(value) < 4 {
			ui.Text(c, "Short: masks may hit other output").FontSize(t.FontSize - 2).TextColor(t.Warning)
		}
		if shown && iconButton(c, "copy", copyIcon, "Copy Value").Clicked() {
			a.copyValue(e.Key, value)
		}
		sensitive := e.Sensitive
		ui.Text(c, "Mask").FontSize(t.FontSize - 1).TextColor(t.TextMuted)
		if toggle(c.Key("mask"), &sensitive).Label("Mask in output").Tooltip("Mask its value in commands' output").Changed() {
			a.report(a.vault.SetSensitive(ns, e.Key, sensitive))
			a.refresh()
		}
		if iconButton(c, "edit", editIcon, "Edit Value").Clicked() {
			// The value shown, if it is, to edit rather than type anew.
			v.form = envForm{open: true, editing: true, key: e.Key, value: value, mask: e.Sensitive}
		}
		if iconButton(c, "delete", trashIcon, "Delete").Clicked() {
			v.deleteKey, v.deleting = e.Key, true
		}
	})
}

// envForm is a row of the env list the user types in: a new env, or a new
// value for key while editing.
type envForm struct {
	open, editing bool
	key, value    string
	mask          bool
	// submit is set by Enter in the value, between frames.
	submit bool
}

// envFormRow is the form's row, laid out as the others: Enter adds or
// saves, Shift+Enter breaks the value's line, and Escape leaves it.
func (a *app) envFormRow(c *ui.Context, ns string) {
	t := c.Theme()
	f := &a.view.form
	key := strings.TrimSpace(f.key)
	if c.Shortcut(0, ui.KeyEscape) {
		f.open = false
		return
	}
	submit := f.submit
	f.submit = false
	// At the top, so that the key and the buttons stay by the value's first
	// line as it grows.
	ui.Row(c.Key("form")).AlignItems(ui.Start).Gap(t.Space(3)).Padding(t.Space(2), 0).Children(func() {
		if f.editing {
			// Padded as the text in an input is, to line up with the value's.
			ui.Text(c, f.key).Font("monospace").Bold().Width(220).Shrink(0).SingleLine().Padding(t.Space(1.5)+1, 0)
		} else {
			k := ui.TextInput(c.Key("key"), &f.key).Placeholder("KEY").Font("monospace").Width(220).Shrink(0).AutoFocus().Label("Key")
			submit = submit || k.Submitted()
		}
		placeholder := "Value"
		if f.editing {
			placeholder = "New value"
		}
		// MinHeight(0): a text area is otherwise three lines high at least.
		value := ui.TextArea(c.Key("value"), &f.value).Lines(1, 6).MinHeight(0).Font("monospace").Placeholder(placeholder).Grow(1).MinWidth(0).Label("Value").
			OnTextKey(func(k ui.TextKey) bool {
				if k.Key != ui.KeyEnter || k.Mods != 0 {
					return false
				}
				f.submit = true
				return true
			})
		if f.editing {
			value.AutoFocus()
		}
		ui.Row(c).AlignItems(ui.Center).Gap(t.Space(3)).Shrink(0).Children(func() {
			ui.Text(c, "Mask").FontSize(t.FontSize - 1).TextColor(t.TextMuted)
			toggle(c.Key("mask"), &f.mask).Label("Mask in output").Tooltip("Mask its value in commands' output")
			label := "Add"
			if f.editing {
				label = "Save"
			}
			if iconButton(c, "submit", checkIcon, label).Disabled(key == "").Clicked() {
				submit = true
			}
			if iconButton(c, "cancel", closeIcon, "Cancel").Clicked() {
				f.open = false
			}
		})
	})
	if !f.editing && a.hasEnv(ns, key) {
		ui.Text(c, key+" is there already: adding replaces its value.").FontSize(t.FontSize-1).TextColor(t.Warning).Padding(0, 0, t.Space(2), 0)
	}
	if !submit || key == "" {
		return
	}
	err := a.vault.SetEnv(ns, key, []byte(f.value))
	if err == nil {
		err = a.vault.SetSensitive(ns, key, f.mask)
	}
	if err != nil {
		a.view.toast = err.Error()
		return
	}
	if a.view.revealed != nil {
		a.view.revealed[key] = f.value
	}
	*f = envForm{}
	a.refresh()
}

func (a *app) envDialogs(c *ui.Context, ns string) {
	v := &a.view
	if confirmDialog(c, &v.deleting, "Delete "+v.deleteKey+"?", "Its value is deleted from "+ns+".", "Cancel", "Delete") {
		a.report(a.vault.DeleteEnv(ns, v.deleteKey))
		delete(v.revealed, v.deleteKey)
		a.refresh()
	}
	message := fmt.Sprintf("Imported %s: %s.\n\nDelete %s, so that the values are no longer in the clear?",
		plural(len(v.imported), "env", "env"), strings.Join(v.imported, ", "), v.importedFrom)
	if confirmDialog(c, &v.askRemove, "Delete the .env file?", message, "Keep It", "Delete") {
		if err := os.Remove(v.importedFrom); err != nil {
			v.toast = err.Error()
		} else {
			v.toast = "Deleted " + v.importedFrom
		}
	}
}

func (a *app) hasEnv(ns, key string) bool {
	for _, n := range a.view.namespaces {
		if n.Name == ns {
			for _, e := range n.Envs {
				if e.Key == key {
					return true
				}
			}
		}
	}
	return false
}

// lock forgets the authorization of a namespace, or of all of them with
// "", and hides the values shown.
func (a *app) lock(name string) {
	if name == "" {
		a.vault.LockAll()
	} else {
		a.vault.Lock(name)
	}
	a.hideValues()
}

// hideValues hides the values shown, and those a reveal under way would.
func (a *app) hideValues() {
	a.view.revealed = nil
	a.view.revealGen++
}

// reveal asks for the namespace's values, to show them.
func (a *app) reveal(ns string) {
	gen := a.view.revealGen
	var secrets []vault.Secret
	a.background(func() (err error) {
		secrets, err = a.vault.Resolve(context.Background(), ns, "show the values of "+ns)
		return err
	}, func(err error) {
		if err != nil {
			a.report(err)
			return
		}
		if a.view.revealedNS == ns && a.view.revealGen == gen {
			a.view.revealed = map[string]string{}
			for _, s := range secrets {
				a.view.revealed[s.Key] = string(s.Value)
			}
		}
	})
}

// clipboardTTL is how long a value copied stays on the clipboard.
const clipboardTTL = time.Minute

// copyValue puts an env's value on the clipboard, and takes it off after
// clipboardTTL unless something else replaced it.
func (a *app) copyValue(key, value string) {
	mygo.Clipboard.WriteText(value)
	a.view.toast = "Copied " + key + ". The clipboard clears in a minute."
	time.AfterFunc(clipboardTTL, func() {
		if mygo.Clipboard.ReadText() == value {
			mygo.Clipboard.Clear()
		}
	})
}

// exportDotenv asks where to write the namespace's env as a .env file,
// then for the user's authorization, and writes it.
func (a *app) exportDotenv(ns string) {
	go func() {
		path, err := mygo.Dialog.Save(mygo.SaveDialogOptions{
			Parent:          a.win,
			Title:           "Export " + ns,
			DefaultPath:     ".env." + ns,
			ButtonLabel:     "Export",
			Message:         "The file holds the values of " + ns + " in the clear, readable only by you.",
			ShowHiddenFiles: true,
		})
		if err != nil || path == "" {
			return
		}
		secrets, err := a.vault.Resolve(context.Background(), ns, "export the values of "+ns)
		if err == nil {
			err = writePrivateFile(path, vault.Dotenv(secrets))
		}
		mygo.RunOnMain(func() {
			if err != nil {
				a.report(err)
			} else {
				a.view.toast = "Exported " + plural(len(secrets), "env", "env") + " to " + path
			}
			a.refresh()
		})
	}()
}

// writePrivateFile replaces the file at path with data, readable and
// writable only by the user, even if it was not.
func writePrivateFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// importDotenv asks for a .env file, imports it into the namespace, and
// offers to delete it.
func (a *app) importDotenv(ns string) {
	go func() {
		paths, err := mygo.Dialog.Open(mygo.OpenDialogOptions{
			Parent:          a.win,
			Title:           "Import .env",
			Message:         "Choose a .env file to import into " + ns + ".",
			ButtonLabel:     "Import",
			ShowHiddenFiles: true,
		})
		if err != nil || len(paths) == 0 {
			return
		}
		data, err := os.ReadFile(paths[0])
		var keys []string
		if err == nil {
			keys, err = a.vault.Import(ns, data)
		}
		mygo.RunOnMain(func() {
			if err != nil {
				a.view.toast = "Import failed: " + err.Error()
				return
			}
			a.view.imported, a.view.importedFrom, a.view.askRemove = keys, paths[0], true
			a.refresh()
		})
	}()
}

// createForm is the New Namespace dialog's.
type createForm struct {
	name, passphrase, confirm string
	generated                 bool
	keychain                  bool
	policy                    int
	ttl                       string
	err                       string
	busy                      bool
}

func (a *app) createDialog(c *ui.Context) {
	t := c.Theme()
	v := &a.view
	f := &v.create
	ui.Modal(c, &v.creating, func() {
		ui.Column(c).Width(520).Gap(t.Space(4)).Children(func() {
			ui.Text(c, "New Vault").FontSize(t.FontSize + 3).Bold()
			group(c, "General", func() {
				settingRow(c, "Name", "Lowercase letters, digits, '.', '_' and '-'.", func() {
					ui.TextInput(c.Key("name"), &f.name).Placeholder("prod-api").AutoFocus().Label("Name").Width(180)
				})
			})
			group(c, "Passphrase", func() {
				settingRow(c, "Passphrase", "Encrypts the vault's key. Keep it safe: it restores the vault without the Keychain.", func() {
					if !f.generated && ui.Button(c, "Generate").Clicked() {
						f.passphrase, f.generated = generatePassphrase(), true
					}
				})
				ui.Column(c).Gap(t.Space(2)).Padding(0, 0, t.Space(3), 0).Children(func() {
					if f.generated {
						ui.Row(c).Gap(t.Space(2)).AlignItems(ui.Center).Padding(t.Space(1), t.Space(2)).Background(t.Surface).Radius(t.Radius).Children(func() {
							ui.Text(c, f.passphrase).Font("monospace").Selectable().Grow(1)
							if iconButton(c, "copy", copyIcon, "Copy").Clicked() {
								mygo.Clipboard.WriteText(f.passphrase)
								v.toast = "Copied the passphrase"
							}
						})
						return
					}
					ui.TextInput(c.Key("pass"), &f.passphrase).Password().Placeholder("Passphrase").Label("Passphrase")
					ui.TextInput(c.Key("confirm"), &f.confirm).Password().Placeholder("Passphrase again").Label("Confirm Passphrase")
				})
				divider(c)
				settingRow(c, "Keep in the Keychain", "Unlock with Touch ID instead of typing it.", func() {
					toggle(c.Key("keychain"), &f.keychain).Label("Keep the passphrase in the Keychain")
				})
			})
			group(c, "Authorization", func() {
				policyRows(c, &f.policy, &f.ttl)
			})
			if f.err != "" {
				ui.Text(c, f.err).TextColor(t.Danger).Wrap()
			}
			ui.Row(c).Gap(t.Space(2)).Justify(ui.End).Margin(t.Space(1), 0, 0, 0).Children(func() {
				if f.busy {
					ui.Spinner(c)
				}
				if ui.Button(c, "Cancel").Clicked() {
					v.creating = false
				}
				if primaryButton(c, "Create").Disabled(f.busy).Clicked() {
					a.createNamespace()
				}
			})
		})
	})
}

func (a *app) createNamespace() {
	f := &a.view.create
	name := strings.TrimSpace(f.name)
	switch {
	case f.passphrase == "":
		f.err = "Choose a passphrase, or generate one."
		return
	case !f.generated && f.passphrase != f.confirm:
		f.err = "The passphrases differ."
		return
	}
	f.busy, f.err = true, ""
	passphrase, keychain, policy := []byte(f.passphrase), f.keychain, policyOf(f.policy, f.ttl)
	a.background(func() error {
		_, err := a.vault.Create(name, passphrase, keychain, policy)
		return err
	}, func(err error) {
		f.busy = false
		if err != nil {
			f.err = err.Error()
			return
		}
		a.view.creating = false
		a.view.page = nsPage(name)
	})
}

// generatePassphrase returns 25 random letters and digits, 125 bits, in
// groups of five to read and type.
func generatePassphrase() string {
	text := strings.ToLower(rand.Text()) // 26 letters and digits, 130 bits
	var groups []string
	for i := 0; i+5 <= len(text); i += 5 {
		groups = append(groups, text[i:i+5])
	}
	return strings.Join(groups, "-")
}

// policyRows are the rows of a group choosing how long an authorization
// lasts.
func policyRows(c *ui.Context, mode *int, ttl *string) {
	settingRow(c, "Ask to authorize", "", func() {
		ui.Segmented(c.Key("policy"), mode, "Every Time", "Once a While", "Once a Session").Label("Ask to authorize")
	})
	if policies[*mode] == vault.TTL {
		divider(c)
		settingRow(c, "Each authorization lasts", "", func() {
			ui.Select(c.Key("ttl"), ttl, ttlLabels()).Label("Each authorization lasts").Width(130)
		})
	}
}

// settingsForm is the namespace settings dialog's.
type settingsForm struct {
	name     string
	policy   int
	ttl      string
	keychain bool
	// newPass is typed twice while changing.
	changing         bool
	newPass, confirm string
	busy             bool
}

// group is a box of settings rows under a heading, as macOS's System
// Settings groups them.
func group(c *ui.Context, heading string, rows func()) {
	t := c.Theme()
	ui.Column(c).Gap(t.Space(1.5)).Children(func() {
		ui.Text(c, heading).FontSize(t.FontSize-1).FontWeight(600).TextColor(t.TextMuted).Padding(0, t.Space(1))
		card(c, rows)
	})
}

// settingRow is a row of a group: what it sets, and what it means, at the
// left, and the controls control builds at the right.
func settingRow(c *ui.Context, label, description string, control func()) {
	t := c.Theme()
	ui.Row(c).AlignItems(ui.Center).Gap(t.Space(4)).Padding(t.Space(2.5), 0).Children(func() {
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(0.5)).Children(func() {
			ui.Text(c, label)
			if description != "" {
				ui.Text(c, description).FontSize(t.FontSize - 1).TextColor(t.TextMuted).Wrap()
			}
		})
		ui.Row(c).Shrink(0).Gap(t.Space(2)).AlignItems(ui.Center).Children(control)
	})
}

func divider(c *ui.Context) {
	ui.Box(c).Height(1).Shrink(0).Background(c.Theme().Border.Alpha(0.6))
}

func settingsFormOf(ns vault.Namespace) settingsForm {
	f := settingsForm{name: ns.Name, keychain: ns.Keychain, ttl: ttls[1].label}
	for i, m := range policies {
		if m == ns.Policy.Mode {
			f.policy = i
		}
	}
	for _, t := range ttls {
		if t.d == ns.Policy.TTL {
			f.ttl = t.label
		}
	}
	return f
}

func (a *app) settingsDialog(c *ui.Context, ns vault.Namespace) {
	t := c.Theme()
	v := &a.view
	f := &v.settings
	ui.Modal(c, &v.nsSettings, func() {
		ui.Column(c).Width(520).Gap(t.Space(4)).Children(func() {
			ui.Row(c).Gap(t.Space(2)).AlignItems(ui.Center).Children(func() {
				ui.Icon(c, lockIcon).Size(18, 18).TextColor(t.Accent)
				ui.Text(c, ns.Name).FontSize(t.FontSize + 3).Bold()
			})
			group(c, "General", func() {
				settingRow(c, "Name", "", func() {
					ui.TextInput(c.Key("name"), &f.name).Width(180).Label("Name")
					if ui.Button(c, "Rename").Disabled(f.name == ns.Name).Clicked() {
						if err := a.vault.Rename(ns.Name, f.name); err != nil {
							v.toast = err.Error()
						} else {
							v.page = nsPage(f.name)
							a.refresh()
						}
					}
				})
			})
			group(c, "Authorization", func() {
				mode, ttl := f.policy, f.ttl
				policyRows(c, &f.policy, &f.ttl)
				if mode != f.policy || ttl != f.ttl {
					// Changing the policy locks the namespace.
					a.report(a.vault.SetPolicy(ns.Name, policyOf(f.policy, f.ttl)))
					a.hideValues()
					a.refresh()
				}
			})
			group(c, "Passphrase", func() {
				settingRow(c, "Keep in the Keychain", "Unlock with Touch ID instead of typing it. Turning it on asks for it once.", func() {
					if toggle(c.Key("keychain"), &f.keychain).Label("Keep the passphrase in the Keychain").Disabled(f.busy).Changed() {
						on := f.keychain
						f.busy = true
						a.background(func() error { return a.vault.SetKeychain(context.Background(), ns.Name, on) }, func(err error) {
							f.busy = false
							if err != nil {
								f.keychain = !on
								a.report(err)
							}
						})
					}
				})
				divider(c)
				if !f.changing {
					settingRow(c, "Change passphrase", "It encrypts the vault's key, and restores the vault without the Keychain.", func() {
						if ui.Button(c, "Change…").Clicked() {
							f.changing = true
						}
					})
					return
				}
				ui.Column(c).Gap(t.Space(2)).Padding(t.Space(3), 0).Children(func() {
					ui.TextInput(c.Key("new-pass"), &f.newPass).Password().Placeholder("New passphrase").Label("New Passphrase").AutoFocus()
					ui.TextInput(c.Key("confirm"), &f.confirm).Password().Placeholder("New passphrase again").Label("Confirm New Passphrase")
					ui.Row(c).Gap(t.Space(2)).Justify(ui.End).Children(func() {
						if ui.Button(c, "Cancel").Disabled(f.busy).Clicked() {
							f.changing, f.newPass, f.confirm = false, "", ""
						}
						ready := f.newPass != "" && f.newPass == f.confirm && !f.busy
						if !primaryButton(c, "Change Passphrase").Disabled(!ready).Clicked() {
							return
						}
						pass := []byte(f.newPass)
						f.busy = true
						a.background(func() error { return a.vault.ChangePassphrase(context.Background(), ns.Name, pass) }, func(err error) {
							f.busy = false
							switch {
							case errors.Is(err, vault.ErrKeychainStale):
								v.toast = "Passphrase changed, but the Keychain kept the old one: the next unlock asks for it once."
							case err != nil:
								a.report(err)
								return
							default:
								v.toast = "Passphrase changed"
							}
							f.changing, f.newPass, f.confirm = false, "", ""
						})
					})
				})
			})
			ui.Row(c).Justify(ui.End).Margin(t.Space(1), 0, 0, 0).Children(func() {
				if primaryButton(c, "Done").Clicked() {
					v.nsSettings = false
				}
			})
		})
	})
}

// deleteDialog asks before deleting deleteNS, while deletingNS.
func (a *app) deleteDialog(c *ui.Context) {
	v := &a.view
	if !confirmDialog(c, &v.deletingNS, "Delete "+v.deleteNS+"?", "Its env and passphrase are deleted for good.", "Cancel", "Delete") {
		return
	}
	// Off the main thread: deleting waits for any question the user is
	// asked, which the main thread draws.
	name := v.deleteNS
	a.background(func() error { return a.vault.Delete(context.Background(), name) }, func(err error) {
		if err != nil {
			v.toast = err.Error()
			return
		}
		if v.page == nsPage(name) {
			v.nsSettings = false
			v.page = pageRuns
		}
	})
}

// --- Runs ---

func (a *app) runsPage(c *ui.Context) {
	t := c.Theme()
	v := &a.view
	subtitle := "Commands run through gatelock"
	if v.running > 0 {
		subtitle = plural(v.running, "running", "running") + " now"
	}
	a.header(c, runsIcon, "Activities", subtitle, nil)
	if len(v.runs) == 0 {
		ui.Column(c).Grow(1).Center().Gap(t.Space(2)).Children(func() {
			ui.Text(c, "No activities yet").FontSize(t.FontSize + 2).TextColor(t.TextMuted)
			ui.Text(c, "gatelock run <vault> -- <command>").Font("monospace").TextColor(t.TextMuted)
		})
		return
	}
	ui.Scroll(c.Key("list")).Grow(1).Children(func() {
		ui.Column(c).Padding(0, t.Space(3), t.Space(3), t.Space(3)).Children(func() {
			ui.Column(c).Shrink(0).Radius(t.Radius).Border(1, t.Border).Clip().Children(func() {
				for i, r := range v.runs {
					a.runItem(c, r, i > 0)
				}
			})
		})
	})
}

// runView is a run the user has opened: its output, which it keeps as it
// closes, to show while the panel shrinks, and the output's scroll, which
// follows the end unless the user scrolls up from it.
type runView struct {
	open   bool
	output string
	scroll ui.ScrollState
}

// runItem is a run as a section of an accordion: a header saying what ran
// and how it went, which opens to show the output below it.
func (a *app) runItem(c *ui.Context, r history.Run, divided bool) {
	t := c.Theme()
	v := &a.view
	rv := v.runViews[r.ID]
	if rv == nil {
		rv = &runView{}
	}
	item := ui.Column(c.Key(r.ID)).Shrink(0)
	if divided {
		item.BorderWidth(1, 0, 0, 0).BorderColor(t.Border)
	}
	item.Children(func() {
		p := ui.CollapsibleBase(c, &rv.open)
		tr := p.Trigger.AlignItems(ui.Center).Gap(t.Space(3)).Padding(t.Space(2), t.Space(3))
		if tr.Hovered() {
			tr.Background(t.SurfaceHover)
		}
		tr.Children(func() {
			ui.Icon(c, chevronIcon).Size(12, 12).Shrink(0).TextColor(t.TextMuted).Rotate(90 * p.Progress())
			statusDot(c, r)
			ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(0.5)).Children(func() {
				ui.Text(c, strings.Join(r.Argv, " ")).Font("monospace").SingleLine().Tooltip(strings.Join(r.Argv, " "))
				ui.Text(c, r.Namespace+"  ·  "+r.Cwd).FontSize(t.FontSize - 1).TextColor(t.TextMuted).SingleLine()
			})
			if note := statusNote(r); note != "" {
				ui.Text(c, note).FontSize(t.FontSize - 1).FontWeight(600).TextColor(statusColor(t, r)).SingleLine()
			}
			ui.Text(c, when(r)).FontSize(t.FontSize - 1).TextColor(t.TextMuted).SingleLine()
			if !r.Status.Ended() {
				label := "Stop"
				if r.Status == history.Authorizing {
					label = "Cancel"
				}
				if iconButton(c, "stop", stopIcon, label).Clicked() {
					a.history.Stop(r.ID)
				}
			}
		})
		if tr.Changed() && rv.open {
			if v.runViews == nil {
				v.runViews = map[string]*runView{}
			}
			rv.scroll = ui.ScrollState{Y: math.MaxFloat32}
			v.runViews[r.ID] = rv
			a.refresh()
		}
		p.Panel(func() {
			if rv.scroll.Y >= rv.scroll.MaxY {
				rv.scroll.Y = math.MaxFloat32
			}
			// Without the last newline, which would show as an empty line.
			out := strings.TrimSuffix(rv.output, "\n")
			if out == "" {
				out = "(no output)"
			}
			ui.Scroll(c.Key("output")).TrackScroll(&rv.scroll).MaxHeight(280).Background(t.Background).Border(1, t.Border).Radius(t.Radius).Children(func() {
				ui.Text(c, out).Font("monospace").FontSize(t.FontSize-1).Selectable().Wrap().Padding(t.Space(2), t.Space(3))
			})
		}).Padding(t.Space(1.5), t.Space(3), t.Space(3), t.Space(9))
	})
}

// statusDot shows a run's status as a dot in a soft halo, as Mux shows an
// agent's: a running command's halo breathes, one waiting for the user to
// authorize it ripples out, an ended one's stays still, as all do for less
// motion. The colors tell the statuses apart without it.
func statusDot(c *ui.Context, r history.Run) {
	t := c.Theme()
	color := statusColor(t, r)
	const size, core = 12, 6
	dot := ui.Box(c.Key("status")).Size(size, size).Shrink(0).Label(statusText(r)).Tooltip(statusText(r))
	still := c.Preferences().ReduceMotion
	// The halo moves as the dot is painted again, without the view built
	// again.
	dot.Draw(func(p *ui.Painter, rect ui.Rect) {
		scale, alpha := float32(1), float32(0.3)
		switch {
		case still:
		case r.Status == history.Running:
			// Out to half again and back, fading, over 2s.
			v := ui.Bounce(ui.CubicBezier(0.42, 0, 0.58, 1))(phase(p.Now(), 2*time.Second))
			scale, alpha = 1+0.5*v, 0.35-0.25*v
			p.AnimationFrame()
		case r.Status == history.Authorizing:
			// Out to more than twice and gone in three quarters of 1.6s,
			// then still till it starts over.
			v := ui.CubicBezier(0, 0, 0.2, 1)(min(phase(p.Now(), 1600*time.Millisecond)/0.75, 1))
			scale, alpha = 1+1.2*v, 0.45*(1-v)
			p.AnimationFrame()
		}
		cx, cy := rect.X+rect.W/2, rect.Y+rect.H/2
		var circle ui.Path
		p.FillPath(circle.Circle(cx, cy, size/2*scale), color.Alpha(alpha))
		p.FillPath(circle.Reset().Circle(cx, cy, core/2), color)
	})
}

// phase is how far along a loop of period now is, from 0 to 1.
func phase(now time.Time, period time.Duration) float32 {
	return float32(now.UnixNano()%int64(period)) / float32(period)
}

func statusColor(t *ui.Theme, r history.Run) ui.Color {
	switch r.Status {
	case history.Running, history.Authorizing:
		// As Mux's working agents: the accent is too near the danger red
		// for a dot to tell apart. The motion tells these two apart.
		return t.Warning
	case history.Exited:
		if r.ExitCode == 0 {
			return t.Success
		}
		return t.Danger
	case history.Failed:
		return t.Danger
	}
	return t.TextMuted
}

// statusNote says what the dot cannot: the code a command exited with,
// unless 0, or how a run ended otherwise. It is "" for a run going on or
// exited with 0.
func statusNote(r history.Run) string {
	switch r.Status {
	case history.Running:
		return ""
	case history.Authorizing:
		return "waiting"
	case history.Exited:
		if r.ExitCode == 0 {
			return ""
		}
		return fmt.Sprintf("exit %d", r.ExitCode)
	}
	return string(r.Status)
}

// statusText describes a run's status in full, for the dot's tooltip.
func statusText(r history.Run) string {
	switch r.Status {
	case history.Authorizing:
		return "Waiting for authorization"
	case history.Running:
		return "Running"
	case history.Exited:
		return fmt.Sprintf("Exited with %d", r.ExitCode)
	case history.Stopped:
		return "Stopped from Gatelock"
	case history.Denied:
		return "Not authorized"
	case history.Failed:
		return "Could not be started"
	}
	return "Lost: gatelock run went away before it ended"
}

// when says when a run started, and how long it took or has taken.
func when(r history.Run) string {
	end := r.EndedAt
	if end.IsZero() {
		end = time.Now()
	}
	took := end.Sub(r.StartedAt).Round(time.Second)
	started := r.StartedAt.Local().Format("Jan 2 15:04")
	if r.StartedAt.Local().YearDay() == time.Now().YearDay() {
		started = r.StartedAt.Local().Format("15:04:05")
	}
	return started + "  ·  " + took.String()
}

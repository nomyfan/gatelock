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
	chosenRun  string
	output     string // of chosenRun
	// outputScroll follows the end of the output, unless the user scrolls
	// up from it.
	outputScroll ui.ScrollState
	toast        string // shown in the next frame

	// The namespace page: the values shown, of revealedNS. revealGen
	// changes as they are hidden, so that a reveal under way then shows
	// nothing.
	revealed   map[string]string
	revealedNS string
	revealGen  int
	newKey     string
	newValue   string
	// editKey's value, being edited while editing.
	editKey   string
	editValue string
	editing   bool
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
	ui.Row(c).Fill().AlignItems(ui.Stretch).Background(t.Background).Children(func() {
		ui.Column(c).Width(220).Shrink(0).Background(t.Surface).Children(func() { a.sidebar(c) })
		ui.Box(c).Width(1).Shrink(0).Background(t.Border)
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
	a.createDialog(c)
}

// titleBand is the height of the band along the top that the window
// controls sit in, the sidebar's top and the pages' headers.
const titleBand = 44

func (a *app) sidebar(c *ui.Context) {
	t := c.Theme()
	v := &a.view
	ui.Box(c).Height(titleBand).Shrink(0).DragWindow()
	ui.Sidebar(c, &v.page, func() {
		item(c, pageRuns, runsIcon, "Runs", v.page, func() {
			if v.running > 0 {
				ui.Text(c, fmt.Sprint(v.running)).FontSize(t.FontSize - 1).TextColor(t.Accent).FontWeight(600)
			}
		})
		item(c, pageSetup, setupIcon, "Setup", v.page, nil)
		ui.Row(c.Key("namespaces")).Height(28).AlignItems(ui.Center).Padding(0, t.Space(1), 0, t.Space(2)).
			Margin(t.Space(3), 0, 0, 0).Shrink(0).Children(func() {
			ui.Text(c, "Namespaces").FontSize(t.FontSize - 1).FontWeight(600).TextColor(t.TextMuted).Grow(1)
			if iconButton(c, "new", plusIcon, "New Namespace").Clicked() {
				v.create = createForm{keychain: true, ttl: ttls[1].label}
				v.creating = true
			}
		})
		for _, ns := range v.namespaces {
			item(c.Key(ns.Name), nsPage(ns.Name), lockIcon, ns.Name, v.page, nil)
		}
		if len(v.namespaces) == 0 {
			ui.Text(c, "None yet").FontSize(t.FontSize-1).TextColor(t.TextMuted).Padding(t.Space(1), t.Space(2))
		}
	}).Grow(1).Label("Pages").Padding(0, t.Space(2))
}

// item is a sidebar item, chosen as Mux shows it: on a darker ground
// rather than the accent, with what trailing builds after its label. Its
// icon is drawn over a blank one, in the accent, since SidebarItem tints
// its own for the accent ground.
func item(c *ui.Context, id string, icon *ui.SVG, label, chosen string, trailing func()) {
	t := c.Theme()
	e := ui.SidebarItem(c, id, blankIcon, label)
	if id == chosen {
		e.Background(t.SurfacePressed).TextColor(t.Text)
	}
	e.Children(func() {
		ui.Box(c).Absolute().Left(t.Space(2)).Top(0).Bottom(0).Center().Children(func() {
			ui.Icon(c, icon).Size(16, 16).TextColor(t.Accent)
		})
		if trailing != nil {
			trailing()
		}
	})
}

// header heads a page along the window's top, as Mux heads its panes:
// the page's icon and title, what it is about, and its actions at the
// right. It drags the window as a title bar would.
func header(c *ui.Context, icon *ui.SVG, title, subtitle string, actions func()) {
	t := c.Theme()
	ui.Row(c).Height(titleBand).Shrink(0).AlignItems(ui.Stretch).Gap(t.Space(2)).Padding(0, t.Space(3), 0, 0).Children(func() {
		// The actions stay out of what drags the window, which would take
		// their clicks.
		ui.Row(c).Grow(1).MinWidth(0).AlignItems(ui.Center).Gap(t.Space(2)).Padding(0, 0, 0, t.Space(5)).DragWindow().Children(func() {
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
	header(c, lockIcon, ns.Name, describePolicy(ns.Policy)+", "+keychain, func() {
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
		if ui.Button(c, "Import .env…").Clicked() {
			a.importDotenv(name)
		}
		if iconButton(c, "settings", settingsIcon, "Settings").Clicked() {
			v.settings = settingsFormOf(ns)
			v.nsSettings = true
		}
	})
	ui.Scroll(c).Grow(1).Children(func() {
		ui.Column(c).Padding(t.Space(1), t.Space(5), t.Space(5), t.Space(5)).Gap(t.Space(4)).Children(func() {
			card(c, func() {
				if len(ns.Envs) == 0 {
					ui.Text(c, "No env yet. Add one below, or import a .env file.").TextColor(t.TextMuted).Padding(t.Space(3), 0)
				}
				for i, e := range ns.Envs {
					if i > 0 {
						ui.Divider(c)
					}
					a.envRow(c, name, e)
				}
			})
			a.addEnvRow(c, name)
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
		sensitive := e.Sensitive
		ui.Text(c, "Mask").FontSize(t.FontSize - 1).TextColor(t.TextMuted)
		if ui.Switch(c.Key("mask"), &sensitive).Label("Mask in output").Tooltip("Mask its value in commands' output").Changed() {
			a.report(a.vault.SetSensitive(ns, e.Key, sensitive))
			a.refresh()
		}
		if iconButton(c, "edit", editIcon, "Edit Value").Clicked() {
			v.editKey, v.editValue, v.editing = e.Key, "", true
		}
		if iconButton(c, "delete", trashIcon, "Delete").Clicked() {
			v.deleteKey, v.deleting = e.Key, true
		}
	})
}

func (a *app) addEnvRow(c *ui.Context, ns string) {
	t := c.Theme()
	v := &a.view
	ui.Row(c).Gap(t.Space(2)).AlignItems(ui.Center).Children(func() {
		key := ui.TextInput(c.Key("new-key"), &v.newKey).Placeholder("KEY").Font("monospace").Width(220).Label("Key")
		value := ui.TextInput(c.Key("new-value"), &v.newValue).Password().Placeholder("Value").Grow(1).Label("Value")
		add := ui.PrimaryButton(c, "Add").Disabled(v.newKey == "")
		if (add.Clicked() || key.Submitted() || value.Submitted()) && v.newKey != "" {
			if err := a.vault.SetEnv(ns, strings.TrimSpace(v.newKey), []byte(v.newValue)); err != nil {
				v.toast = err.Error()
				return
			}
			if v.revealed != nil {
				v.revealed[strings.TrimSpace(v.newKey)] = v.newValue
			}
			v.newKey, v.newValue = "", ""
			a.refresh()
		}
	})
}

func (a *app) envDialogs(c *ui.Context, ns string) {
	t := c.Theme()
	v := &a.view
	ui.Modal(c, &v.editing, func() {
		ui.Text(c, "Edit "+v.editKey).Bold()
		ui.Text(c, "The new value replaces the one stored.").TextColor(t.TextMuted).FontSize(t.FontSize - 1)
		ui.TextInput(c.Key("edit-value"), &v.editValue).Lines(3, 10).Font("monospace").Width(420).AutoFocus().Label("Value")
		ui.Row(c).Gap(t.Space(2)).Justify(ui.End).Children(func() {
			if ui.Button(c, "Cancel").Clicked() {
				v.editing = false
			}
			if ui.PrimaryButton(c, "Save").Clicked() {
				if err := a.vault.SetEnv(ns, v.editKey, []byte(v.editValue)); err != nil {
					v.toast = err.Error()
				} else if v.revealed != nil {
					v.revealed[v.editKey] = v.editValue
				}
				v.editing, v.editValue = false, ""
				a.refresh()
			}
		})
	})
	if ui.AlertDialog(c, &v.deleting, "Delete "+v.deleteKey+"?", "Its value is deleted from "+ns+".", "Cancel", "Delete") == 1 {
		a.report(a.vault.DeleteEnv(ns, v.deleteKey))
		delete(v.revealed, v.deleteKey)
		a.refresh()
	}
	message := fmt.Sprintf("Imported %s: %s.\n\nDelete %s, so that the values are no longer in the clear?",
		plural(len(v.imported), "env", "env"), strings.Join(v.imported, ", "), v.importedFrom)
	if ui.AlertDialog(c, &v.askRemove, "Delete the .env file?", message, "Keep It", "Delete") == 1 {
		if err := os.Remove(v.importedFrom); err != nil {
			v.toast = err.Error()
		} else {
			v.toast = "Deleted " + v.importedFrom
		}
	}
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
		ui.Column(c).Width(440).Gap(t.Space(3)).Children(func() {
			ui.Text(c, "New Namespace").FontSize(t.FontSize + 3).Bold()
			field(c, "Name", "Lowercase letters, digits, '.', '_' and '-'.", func() {
				ui.TextInput(c.Key("name"), &f.name).Placeholder("prod-api").AutoFocus().Label("Name")
			})
			field(c, "Passphrase", "Encrypts the namespace's key. Keep it safe: it restores the namespace without the Keychain.", func() {
				if f.generated {
					ui.Row(c).Gap(t.Space(2)).AlignItems(ui.Center).Children(func() {
						ui.Text(c, f.passphrase).Font("monospace").Selectable().Grow(1)
						if iconButton(c, "copy", copyIcon, "Copy").Clicked() {
							mygo.Clipboard.WriteText(f.passphrase)
							v.toast = "Copied the passphrase"
						}
					})
					return
				}
				ui.TextInput(c.Key("pass"), &f.passphrase).Password().Placeholder("Passphrase").Label("Passphrase")
				ui.TextInput(c.Key("confirm"), &f.confirm).Password().Placeholder("Again").Label("Confirm Passphrase")
				ui.Row(c).Children(func() {
					if ui.Button(c, "Generate One").Clicked() {
						f.passphrase, f.generated = generatePassphrase(), true
					}
				})
			})
			ui.Row(c).AlignItems(ui.Center).Gap(t.Space(3)).Children(func() {
				ui.Column(c).Grow(1).Children(func() {
					ui.Text(c, "Keep the passphrase in the Keychain")
					ui.Text(c, "Unlock with Touch ID instead of typing it.").FontSize(t.FontSize - 1).TextColor(t.TextMuted)
				})
				ui.Switch(c.Key("keychain"), &f.keychain).Label("Keep the passphrase in the Keychain")
			})
			policyField(c, &f.policy, &f.ttl)
			if f.err != "" {
				ui.Text(c, f.err).TextColor(t.Danger).Wrap()
			}
			ui.Row(c).Gap(t.Space(2)).Justify(ui.End).Children(func() {
				if f.busy {
					ui.Spinner(c)
				}
				if ui.Button(c, "Cancel").Clicked() {
					v.creating = false
				}
				if ui.PrimaryButton(c, "Create").Disabled(f.busy).Clicked() {
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

func field(c *ui.Context, label, description string, control func()) {
	t := c.Theme()
	ui.Column(c).Gap(t.Space(1)).Children(func() {
		ui.Text(c, label).FontWeight(600)
		if description != "" {
			ui.Text(c, description).FontSize(t.FontSize - 1).TextColor(t.TextMuted).Wrap()
		}
		control()
	})
}

// policyField chooses how long an authorization lasts.
func policyField(c *ui.Context, mode *int, ttl *string) {
	t := c.Theme()
	ui.Column(c).Gap(t.Space(1)).Children(func() {
		ui.Text(c, "Ask to authorize").FontWeight(600)
		ui.Row(c).Children(func() {
			ui.Segmented(c.Key("policy"), mode, "Every Time", "Once a While", "Once a Session").Label("Ask to authorize")
		})
		if policies[*mode] == vault.TTL {
			ui.Row(c).Gap(t.Space(2)).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "Each authorization lasts").TextColor(t.TextMuted)
				ui.Select(c.Key("ttl"), ttl, ttlLabels()).Label("Each authorization lasts").Width(130)
			})
		}
	})
}

// settingsForm is the namespace settings dialog's.
type settingsForm struct {
	name             string
	policy           int
	ttl              string
	keychain         bool
	newPass, confirm string
	busy             bool
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
		ui.Column(c).Width(460).Gap(t.Space(4)).Children(func() {
			ui.Text(c, ns.Name+" Settings").FontSize(t.FontSize + 3).Bold()
			field(c, "Name", "", func() {
				ui.Row(c).Gap(t.Space(2)).Children(func() {
					ui.TextInput(c.Key("name"), &f.name).Grow(1).Label("Name")
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
			mode, ttl := f.policy, f.ttl
			policyField(c, &f.policy, &f.ttl)
			if mode != f.policy || ttl != f.ttl {
				// Changing the policy locks the namespace.
				a.report(a.vault.SetPolicy(ns.Name, policyOf(f.policy, f.ttl)))
				a.hideValues()
				a.refresh()
			}
			ui.Row(c).AlignItems(ui.Center).Gap(t.Space(3)).Children(func() {
				ui.Column(c).Grow(1).Children(func() {
					ui.Text(c, "Keep the passphrase in the Keychain")
					ui.Text(c, "Turning it on asks for the passphrase once.").FontSize(t.FontSize - 1).TextColor(t.TextMuted)
				})
				if ui.Switch(c.Key("keychain"), &f.keychain).Label("Keep the passphrase in the Keychain").Disabled(f.busy).Changed() {
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
			field(c, "Change Passphrase", "", func() {
				ui.TextInput(c.Key("new-pass"), &f.newPass).Password().Placeholder("New passphrase").Label("New Passphrase")
				ui.TextInput(c.Key("confirm"), &f.confirm).Password().Placeholder("Again").Label("Confirm New Passphrase")
				ready := f.newPass != "" && f.newPass == f.confirm && !f.busy
				ui.Row(c).Children(func() {
					if !ui.Button(c, "Change Passphrase").Disabled(!ready).Clicked() {
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
						default:
							f.newPass, f.confirm = "", ""
							v.toast = "Passphrase changed"
						}
					})
				})
			})
			ui.Divider(c)
			ui.Row(c).Gap(t.Space(2)).Children(func() {
				if ui.Button(c, "Delete Namespace…").TextColor(t.Danger).Clicked() {
					v.deletingNS = true
				}
				ui.Box(c).Grow(1)
				if ui.PrimaryButton(c, "Done").Clicked() {
					v.nsSettings = false
				}
			})
		})
	})
	if ui.AlertDialog(c, &v.deletingNS, "Delete "+ns.Name+"?", "Its env and passphrase are deleted for good.", "Cancel", "Delete") == 1 {
		// Off the main thread: deleting waits for any question the user
		// is asked, which the main thread draws.
		name := ns.Name
		a.background(func() error { return a.vault.Delete(context.Background(), name) }, func(err error) {
			if err != nil {
				v.toast = err.Error()
				return
			}
			v.nsSettings = false
			if v.page == nsPage(name) {
				v.page = pageRuns
			}
		})
	}
}

// --- Runs ---

func (a *app) runsPage(c *ui.Context) {
	t := c.Theme()
	v := &a.view
	subtitle := "Commands run through gatelock"
	if v.running > 0 {
		subtitle = plural(v.running, "running", "running") + " now"
	}
	header(c, runsIcon, "Runs", subtitle, nil)
	if len(v.runs) == 0 {
		ui.Column(c).Grow(1).Center().Gap(t.Space(2)).Children(func() {
			ui.Text(c, "No runs yet").FontSize(t.FontSize + 2).TextColor(t.TextMuted)
			ui.Text(c, "gatelock run <namespace> -- <command>").Font("monospace").TextColor(t.TextMuted)
		})
		return
	}
	ui.Scroll(c.Key("list")).Grow(1).Children(func() {
		ui.Column(c).Padding(0, t.Space(3), t.Space(3), t.Space(3)).Gap(t.Space(0.5)).Children(func() {
			for _, r := range v.runs {
				a.runRow(c, r)
			}
		})
	})
	if v.chosenRun != "" {
		ui.Box(c).Height(1).Shrink(0).Background(t.Border)
		ui.Column(c.Key("output")).Height(260).Shrink(0).Background(t.Surface).Children(func() {
			ui.Row(c).Padding(t.Space(2), t.Space(4)).AlignItems(ui.Center).Children(func() {
				ui.Text(c, "Output, masked").FontWeight(600).Grow(1)
				if ui.Button(c, "Close").Clicked() {
					v.chosenRun, v.output = "", ""
				}
			})
			if v.outputScroll.Y >= v.outputScroll.MaxY {
				v.outputScroll.Y = math.MaxFloat32
			}
			ui.Scroll(c.Key(v.chosenRun)).TrackScroll(&v.outputScroll).Grow(1).Children(func() {
				out := v.output
				if out == "" {
					out = "(no output)"
				}
				ui.Text(c, out).Font("monospace").FontSize(t.FontSize-1).Selectable().Wrap().Padding(0, t.Space(4), t.Space(3), t.Space(4))
			})
		})
	}
}

func (a *app) runRow(c *ui.Context, r history.Run) {
	t := c.Theme()
	v := &a.view
	row := ui.Row(c.Key(r.ID)).AlignItems(ui.Center).Gap(t.Space(3)).Padding(t.Space(2), t.Space(2)).Radius(t.Radius)
	if r.ID == v.chosenRun {
		row.Background(t.SurfacePressed)
	} else if row.Hovered() {
		row.Background(t.SurfaceHover)
	}
	if row.Clicked() {
		v.chosenRun, v.outputScroll = r.ID, ui.ScrollState{Y: math.MaxFloat32}
		a.refresh()
	}
	row.Children(func() {
		statusBadge(c, r)
		ui.Column(c).Grow(1).MinWidth(0).Gap(t.Space(0.5)).Children(func() {
			ui.Text(c, strings.Join(r.Argv, " ")).Font("monospace").SingleLine().Tooltip(strings.Join(r.Argv, " "))
			ui.Text(c, r.Namespace+"  ·  "+r.Cwd).FontSize(t.FontSize - 1).TextColor(t.TextMuted).SingleLine()
		})
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
}

func statusBadge(c *ui.Context, r history.Run) {
	t := c.Theme()
	label, color := string(r.Status), t.TextMuted
	switch r.Status {
	case history.Running:
		color = t.Accent
	case history.Authorizing:
		label, color = "waiting", t.Warning
	case history.Exited:
		label, color = fmt.Sprintf("exit %d", r.ExitCode), t.Success
		if r.ExitCode != 0 {
			color = t.Danger
		}
	case history.Failed:
		color = t.Danger
	}
	ui.Text(c, label).FontSize(t.FontSize-2).FontWeight(600).TextColor(color).SingleLine().
		Padding(t.Space(0.5), t.Space(1.5)).Border(1, color.Alpha(0.5)).Radius(t.Space(1)).Width(76).Shrink(0)
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

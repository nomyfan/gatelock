package main

import (
	"embed"

	"github.com/egoist/mygo/ui"

	"gatelock/internal/caller"
)

// The app's colors are Vellum's: a warm theme in a light and a dark
// kind.
var lightTheme, darkTheme = func() (light, dark *ui.Theme) {
	light = ui.LightTheme()
	light.Background = ui.Hex("#faf8f5")
	light.Surface = ui.Hex("#f2efec")
	light.SurfaceHover = ui.Hex("#ebe5de")
	light.SurfacePressed = ui.Hex("#e3dcd4")
	light.Border = ui.Hex("#e8e2da")
	light.Text = ui.Hex("#45413d")
	light.TextMuted = ui.Hex("#6f6861")
	light.Accent = ui.Hex("#b1632f")
	light.AccentHover = ui.Hex("#c08157")
	light.AccentPressed = ui.Hex("#c7906a")
	light.AccentText = ui.Hex("#ffffff")
	light.Danger = ui.Hex("#b75051")
	light.Warning = ui.Hex("#8e6c00")
	light.Success = ui.Hex("#507c39")
	light.Selection = ui.Hex("#dfd7cd")
	light.Focus = light.Accent.Alpha(0.5)
	light.Scrollbar = light.Text.Alpha(0.3)
	// Compact, so that text controls stand as tall as iconButtons, and as
	// tall as AppKit's for text of this size.
	light.Spacing = 3

	dark = ui.DarkTheme()
	dark.Background = ui.Hex("#1a1816")
	dark.Surface = ui.Hex("#151311")
	dark.SurfaceHover = ui.Hex("#24221f")
	dark.SurfacePressed = ui.Hex("#413b35")
	dark.Border = ui.Hex("#3e3934")
	dark.Text = ui.Hex("#d8d3cb")
	dark.TextMuted = ui.Hex("#948d85")
	dark.Accent = ui.Hex("#e6a67e")
	dark.AccentHover = ui.Hex("#bd8a69")
	dark.AccentPressed = ui.Hex("#a97b5f")
	dark.AccentText = ui.Hex("#1a1816")
	dark.Danger = ui.Hex("#e68585")
	dark.Warning = ui.Hex("#e0a84a")
	dark.Success = ui.Hex("#a6c485")
	dark.Selection = ui.Hex("#413b35")
	dark.Focus = dark.Accent.Alpha(0.5)
	dark.Scrollbar = dark.Text.Alpha(0.3)
	dark.Spacing = light.Spacing
	return light, dark
}()

// setTheme colors the frame in Vellum's light or dark kind, as the system
// appears.
func setTheme(c *ui.Context) {
	if c.Theme().Dark {
		c.SetTheme(darkTheme)
	} else {
		c.SetTheme(lightTheme)
	}
}

// The icons are drawn on a 16px grid in currentColor, one file each.
//
//go:embed icons/ui/*.svg
var iconFiles embed.FS

// icon parses icons/ui/<name>.svg.
func icon(name string) *ui.SVG {
	data, err := iconFiles.ReadFile("icons/ui/" + name + ".svg")
	if err != nil {
		panic(err)
	}
	return ui.MustParseSVG(data)
}

var (
	blankIcon      = icon("blank")
	lockIcon       = icon("lock")
	unlockIcon     = icon("unlock")
	activitiesIcon = icon("activities")
	setupIcon      = icon("setup")
	plusIcon       = icon("plus")
	eyeIcon        = icon("eye")
	eyeOffIcon     = icon("eye-off")
	editIcon       = icon("edit")
	trashIcon      = icon("trash")
	settingsIcon   = icon("settings")
	copyIcon       = icon("copy")
	fileIcon       = icon("file")
	stopIcon       = icon("stop")
	sidebarIcon    = icon("sidebar")
	chevronIcon    = icon("chevron")
	checkIcon      = icon("check")
	closeIcon      = icon("close")

	// An activity's status, beside it in the list.
	succeededIcon = icon("status-succeeded")
	exitedIcon    = icon("status-exited")
	failedIcon    = icon("status-failed")
	deniedIcon    = icon("status-denied")
	stoppedIcon   = icon("status-stopped")
	lostIcon      = icon("status-lost")
)

var (
	//go:embed icons/agents/claude.svg
	claudeMark []byte
	//go:embed icons/agents/codex.svg
	codexMark []byte
)

// agentMarks are the agents' own marks in their own colors, by the names
// internal/caller gives them.
var agentMarks = map[string]*ui.SVG{
	caller.ClaudeCode: ui.MustParseSVG(claudeMark),
	caller.Codex:      ui.MustParseSVG(codexMark),
}

// primaryButton is a PrimaryButton as tall as the other controls, which
// its lack of a border would otherwise make 2 shorter.
func primaryButton(c *ui.Context, label string) ui.Element {
	t := c.Theme()
	return ui.PrimaryButton(c, label).Padding(t.Space(1.5)+1, t.Space(3.5))
}

// confirmDialog asks, while *open, whether to do what confirm names, and
// reports whether the user clicked it. It stands in for ui.AlertDialog,
// whose width follows the theme's spacing, which is too narrow in ours.
func confirmDialog(c *ui.Context, open *bool, title, message, cancel, confirm string) bool {
	t := c.Theme()
	confirmed := false
	ui.Modal(c, open, func() {
		ui.Column(c).Width(400).Gap(t.Space(3)).Shrink(1).MinHeight(0).Children(func() {
			ui.Text(c, title).FontSize(t.FontSize + 3).Bold().Wrap().Shrink(0)
			// A long message scrolls, so that the buttons stay in the window.
			ui.Scroll(c.Key("message")).Shrink(1).MinHeight(0).Children(func() {
				ui.Text(c, message).TextColor(t.TextMuted).Wrap()
			})
			ui.Row(c).Gap(t.Space(2)).Justify(ui.End).Margin(t.Space(3), 0, 0, 0).Shrink(0).Children(func() {
				if ui.Button(c, cancel).Clicked() {
					*open = false
				}
				if primaryButton(c, confirm).AutoFocus().Clicked() {
					*open, confirmed = false, true
				}
			})
		})
	}).Role(ui.RoleAlertDialog).Label(title).Description(message)
	return confirmed
}

// toggle is a switch three quarters as tall as the other controls, as
// AppKit's: a compact theme's own would be smaller still.
func toggle(c *ui.Context, on *bool) ui.Element {
	return ui.Switch(c, on).Size(32, 18).Radius(9)
}

// copyable is a button showing what content builds, text that a click
// copies, which label names and tip, its tooltip, says more of. It is
// highlighted while hovered, as plain text would not show it can be
// clicked. It shrinks, unlike a button, so that long text ends in an
// ellipsis rather than overlapping what follows.
func copyable(c *ui.Context, key, label, tip string, content func()) ui.Element {
	t := c.Theme()
	b := ui.ButtonBase(c.Key(key)).Padding(2, copyInset(c)).Radius(4).Shrink(1).MinWidth(0).Cursor(ui.CursorPointer).
		Label(label).Tooltip(tip)
	if b.Pressed() {
		b.Background(t.Text.Alpha(0.14))
	} else if b.Hovered() {
		b.Background(t.Text.Alpha(0.08))
	}
	b.Children(content)
	return b
}

// copyInset is copyable's inset of its text, an input's, so that the text
// lines up with the env form's.
func copyInset(c *ui.Context) float32 { return c.Theme().Space(1.5) + 1 }

// iconButton is a small button showing an icon, which its label names.
func iconButton(c *ui.Context, key string, icon *ui.SVG, label string) ui.Element {
	t := c.Theme()
	b := ui.ButtonBase(c.Key(key)).Size(26, 26).Radius(6).Center().TextColor(t.TextMuted).Label(label).Tooltip(label)
	if b.Pressed() {
		b.Background(t.Text.Alpha(0.14))
	} else if b.Hovered() {
		b.Background(t.Text.Alpha(0.08)).TextColor(t.Text)
	}
	b.Children(func() { ui.Icon(c, icon).Size(15, 15) })
	return b
}

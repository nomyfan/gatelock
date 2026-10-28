package main

import "github.com/egoist/mygo/ui"

// The app's colors are Vellum's: a warm theme in a light and a dark
// kind.
var lightTheme, darkTheme = func() (light, dark *ui.Theme) {
	light = ui.LightTheme()
	light.Background = ui.Hex("#faf8f5")
	light.Surface = ui.Hex("#efeae4")
	light.SurfaceHover = ui.Hex("#e7e0d8")
	light.SurfacePressed = ui.Hex("#e0d6cc")
	light.Border = ui.Hex("#cbbdae")
	light.Text = ui.Hex("#45413d")
	light.TextMuted = ui.Hex("#8a837b")
	light.Accent = ui.Hex("#b8622a")
	light.AccentHover = ui.Hex("#a2561f")
	light.AccentPressed = ui.Hex("#8e4b1a")
	light.AccentText = ui.Hex("#faf8f5")
	light.Danger = ui.Hex("#b75051")
	light.Warning = ui.Hex("#b3760f")
	light.Success = ui.Hex("#507c39")
	light.Selection = ui.Hex("#d5cbc2")
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
	dark.TextMuted = ui.Hex("#7c7670")
	dark.Accent = ui.Hex("#cf9370")
	dark.AccentHover = ui.Hex("#d9a07f")
	dark.AccentPressed = ui.Hex("#c4865f")
	dark.AccentText = ui.Hex("#1a1816")
	dark.Danger = ui.Hex("#e68585")
	dark.Warning = ui.Hex("#e0a84a")
	dark.Success = ui.Hex("#a6c485")
	dark.Selection = ui.Hex("#413b35")
	dark.Focus = dark.Accent.Alpha(0.6)
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

func icon(shapes string) *ui.SVG {
	return ui.MustParseSVG([]byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">` + shapes + `</svg>`))
}

var (
	blankIcon      = icon(``)
	lockIcon       = icon(`<rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>`)
	activitiesIcon = icon(`<path d="M1.5 8.5h2.5l2-5 4 9 2-4h2.5"/>`)
	setupIcon      = icon(`<path d="M6 1.5v3M10 1.5v3M4 4.5h8V7a4 4 0 0 1-8 0zM8 11v3.5"/>`)
	plusIcon       = icon(`<path d="M8 3v10M3 8h10"/>`)
	eyeIcon        = icon(`<path d="M1.5 8s2.4-4.5 6.5-4.5S14.5 8 14.5 8s-2.4 4.5-6.5 4.5S1.5 8 1.5 8z"/><circle cx="8" cy="8" r="2"/>`)
	eyeOffIcon     = icon(`<path d="M2 2l12 12M6.6 6.6a2 2 0 0 0 2.8 2.8M4.2 4.4C2.5 5.6 1.5 8 1.5 8s2.4 4.5 6.5 4.5c1.3 0 2.4-.4 3.3-1M7 3.6c.3 0 .7-.1 1-.1 4.1 0 6.5 4.5 6.5 4.5s-.5 1-1.5 2.1"/>`)
	editIcon       = icon(`<path d="M10.5 2.5l3 3L6 13H3v-3z"/>`)
	trashIcon      = icon(`<path d="M2.5 4h11M6 4V2.5h4V4M4 4l.7 9.5h6.6L12 4"/>`)
	settingsIcon   = icon(`<path d="M2 4h7M12 4h2M2 12h2M7 12h7M2 8h4M9 8h5"/><circle cx="10.5" cy="4" r="1.5"/><circle cx="5.5" cy="12" r="1.5"/><circle cx="7.5" cy="8" r="1.5"/>`)
	copyIcon       = icon(`<rect x="5" y="5" width="8.5" height="8.5" rx="1.5"/><path d="M11 5V3.5A1 1 0 0 0 10 2.5H3.5a1 1 0 0 0-1 1V10a1 1 0 0 0 1 1H5"/>`)
	fileIcon       = icon(`<path d="M9.5 1.5H4.5a1 1 0 0 0-1 1v11a1 1 0 0 0 1 1h7a1 1 0 0 0 1-1v-8.5z"/><path d="M9.5 1.5v4h3M6 9h4M6 11.5h4"/>`)
	stopIcon       = icon(`<rect x="4" y="4" width="8" height="8" rx="1"/>`)
	sidebarIcon    = icon(`<rect x="1.5" y="2.5" width="13" height="11" rx="2"/><path d="M6 2.5v11"/>`)
	chevronIcon    = icon(`<path d="M6 3.5L10.5 8 6 12.5"/>`)
	checkIcon      = icon(`<path d="M3 8.5l3.5 3.5L13 4.5"/>`)
	closeIcon      = icon(`<path d="M4 4l8 8M12 4l-8 8"/>`)
)

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
		ui.Column(c).Width(400).Gap(t.Space(3)).Children(func() {
			ui.Text(c, title).FontSize(t.FontSize + 3).Bold().Wrap()
			ui.Text(c, message).TextColor(t.TextMuted).Wrap()
			ui.Row(c).Gap(t.Space(2)).Justify(ui.End).Margin(t.Space(3), 0, 0, 0).Children(func() {
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
// copies, which label names. It is highlighted while hovered, as plain
// text would not show it can be clicked.
func copyable(c *ui.Context, key, label string, content func()) ui.Element {
	t := c.Theme()
	b := ui.ButtonBase(c.Key(key)).Padding(2, copyInset(c)).Radius(4).MinWidth(0).Cursor(ui.CursorPointer).
		Label(label).Tooltip("Click to copy")
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

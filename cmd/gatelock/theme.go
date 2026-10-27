package main

import "github.com/egoist/mygo/ui"

// The app's colors are Vellum's, as Mux has them: a warm theme in a light
// and a dark kind.
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
	blankIcon    = icon(``)
	lockIcon     = icon(`<rect x="3" y="7" width="10" height="7" rx="1.5"/><path d="M5.5 7V5a2.5 2.5 0 0 1 5 0v2"/>`)
	runsIcon     = icon(`<rect x="2" y="3" width="12" height="10" rx="1.5"/><path d="M5 7l2 1.5L5 10M8.5 10h2.5"/>`)
	setupIcon    = icon(`<circle cx="8" cy="8" r="2"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M3.4 12.6l1.4-1.4M11.2 4.8l1.4-1.4"/>`)
	plusIcon     = icon(`<path d="M8 3v10M3 8h10"/>`)
	eyeIcon      = icon(`<path d="M1.5 8s2.4-4.5 6.5-4.5S14.5 8 14.5 8s-2.4 4.5-6.5 4.5S1.5 8 1.5 8z"/><circle cx="8" cy="8" r="2"/>`)
	eyeOffIcon   = icon(`<path d="M2 2l12 12M6.6 6.6a2 2 0 0 0 2.8 2.8M4.2 4.4C2.5 5.6 1.5 8 1.5 8s2.4 4.5 6.5 4.5c1.3 0 2.4-.4 3.3-1M7 3.6c.3 0 .7-.1 1-.1 4.1 0 6.5 4.5 6.5 4.5s-.5 1-1.5 2.1"/>`)
	editIcon     = icon(`<path d="M10.5 2.5l3 3L6 13H3v-3z"/>`)
	trashIcon    = icon(`<path d="M2.5 4h11M6 4V2.5h4V4M4 4l.7 9.5h6.6L12 4"/>`)
	settingsIcon = icon(`<path d="M2 4h7M12 4h2M2 12h2M7 12h7M2 8h4M9 8h5"/><circle cx="10.5" cy="4" r="1.5"/><circle cx="5.5" cy="12" r="1.5"/><circle cx="7.5" cy="8" r="1.5"/>`)
	copyIcon     = icon(`<rect x="5" y="5" width="8.5" height="8.5" rx="1.5"/><path d="M11 5V3.5A1 1 0 0 0 10 2.5H3.5a1 1 0 0 0-1 1V10a1 1 0 0 0 1 1H5"/>`)
	stopIcon     = icon(`<rect x="4" y="4" width="8" height="8" rx="1"/>`)
)

// iconButton is a small button showing an icon, which its label names.
func iconButton(c *ui.Context, key string, icon *ui.SVG, label string) ui.Element {
	t := c.Theme()
	b := ui.ButtonBase(c.Key(key)).Size(26, 24).Radius(6).Center().TextColor(t.TextMuted).Label(label).Tooltip(label)
	if b.Pressed() {
		b.Background(t.Text.Alpha(0.14))
	} else if b.Hovered() {
		b.Background(t.Text.Alpha(0.08)).TextColor(t.Text)
	}
	b.Children(func() { ui.Icon(c, icon).Size(15, 15) })
	return b
}

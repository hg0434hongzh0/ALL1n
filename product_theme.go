package main

import (
	"image/color"
	"path/filepath"
	"runtime"
	"sync"

	"fyne.io/fyne/v2"
	fyneTheme "fyne.io/fyne/v2/theme"
)

const (
	colorNameSurface       fyne.ThemeColorName = "all1n.surface"
	colorNameSurfaceBorder fyne.ThemeColorName = "all1n.surfaceBorder"
)

const (
	defaultThemeID = "midnight"
	defaultFontID  = "deng"
)

type appearanceOption struct {
	ID    string
	Label string
}

var productThemeOptions = []appearanceOption{
	{ID: "midnight", Label: "深海蓝"},
	{ID: "aurora", Label: "极光青"},
	{ID: "graphite", Label: "石墨紫"},
	{ID: "daylight", Label: "云雾白"},
}

var productFontOptions = []appearanceOption{
	{ID: "deng", Label: "现代等线"},
	{ID: "heiti", Label: "清晰黑体"},
	{ID: "system", Label: "系统默认"},
}

type productPalette struct {
	variant                                      fyne.ThemeVariant
	background, surface, surfaceBorder           color.Color
	button, disabledButton, foreground, disabled color.Color
	primary, focus, hover, selection             color.Color
	input, separator, shadow                     color.Color
	success, warning, failure                    color.Color
}

type productTheme struct {
	base       fyne.Theme
	palette    productPalette
	fontID     string
	fontNormal fyne.Resource
	fontBold   fyne.Resource
}

func newProductTheme(themeID, fontID string) fyne.Theme {
	palette := paletteForTheme(themeID)
	base := fyneTheme.DarkTheme()
	if palette.variant == fyneTheme.VariantLight {
		base = fyneTheme.LightTheme()
	}
	normal, bold := productFonts(fontID)
	return &productTheme{
		base:       base,
		palette:    palette,
		fontID:     normalizedOptionID(productFontOptions, fontID, defaultFontID),
		fontNormal: normal,
		fontBold:   bold,
	}
}

func (t *productTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	p := t.palette
	switch name {
	case colorNameSurface:
		return p.surface
	case colorNameSurfaceBorder:
		return p.surfaceBorder
	case fyneTheme.ColorNameBackground:
		return p.background
	case fyneTheme.ColorNameButton:
		return p.button
	case fyneTheme.ColorNameDisabledButton:
		return p.disabledButton
	case fyneTheme.ColorNameForeground:
		return p.foreground
	case fyneTheme.ColorNameDisabled, fyneTheme.ColorNamePlaceHolder:
		return p.disabled
	case fyneTheme.ColorNamePrimary:
		return p.primary
	case fyneTheme.ColorNameFocus:
		return p.focus
	case fyneTheme.ColorNameHover:
		return p.hover
	case fyneTheme.ColorNameSelection:
		return p.selection
	case fyneTheme.ColorNameInputBackground:
		return p.input
	case fyneTheme.ColorNameSeparator:
		return p.separator
	case fyneTheme.ColorNameShadow:
		return p.shadow
	case fyneTheme.ColorNameSuccess:
		return p.success
	case fyneTheme.ColorNameWarning:
		return p.warning
	case fyneTheme.ColorNameError:
		return p.failure
	default:
		return t.base.Color(name, p.variant)
	}
}

func (t *productTheme) Font(style fyne.TextStyle) fyne.Resource {
	if style.Monospace || t.fontID == "system" || t.fontNormal == nil {
		return t.base.Font(style)
	}
	if style.Bold && t.fontBold != nil {
		return t.fontBold
	}
	return t.fontNormal
}

func (t *productTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return t.base.Icon(name)
}

func (t *productTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case fyneTheme.SizeNameText:
		return 14
	case fyneTheme.SizeNameCaptionText:
		return 12
	case fyneTheme.SizeNameHeadingText:
		return 23
	case fyneTheme.SizeNameSubHeadingText:
		return 17
	case fyneTheme.SizeNamePadding:
		return 8
	case fyneTheme.SizeNameInnerPadding:
		return 10
	}
	return t.base.Size(name)
}

func paletteForTheme(id string) productPalette {
	switch normalizedOptionID(productThemeOptions, id, defaultThemeID) {
	case "aurora":
		return productPalette{
			variant:    fyneTheme.VariantDark,
			background: rgba(0x06, 0x10, 0x0F), surface: rgba(0x0A, 0x1B, 0x18), surfaceBorder: rgba(0x1D, 0x4A, 0x41),
			button: rgba(0x12, 0x31, 0x2A), disabledButton: rgba(0x0C, 0x20, 0x1C), foreground: rgba(0xE8, 0xFF, 0xF8), disabled: rgba(0x78, 0xA5, 0x99),
			primary: rgba(0x2D, 0xD4, 0xBF), focus: rgbaA(0x2D, 0xD4, 0xBF, 0x99), hover: rgbaA(0x25, 0x59, 0x4E, 0xCC), selection: rgba(0x10, 0x69, 0x5D),
			input: rgba(0x0B, 0x21, 0x1C), separator: rgba(0x1D, 0x4A, 0x41), shadow: rgbaA(0, 0, 0, 0x80),
			success: rgba(0x34, 0xD3, 0x99), warning: rgba(0xFB, 0xBF, 0x24), failure: rgba(0xFB, 0x71, 0x85),
		}
	case "graphite":
		return productPalette{
			variant:    fyneTheme.VariantDark,
			background: rgba(0x10, 0x11, 0x15), surface: rgba(0x18, 0x1A, 0x21), surfaceBorder: rgba(0x3A, 0x3D, 0x49),
			button: rgba(0x27, 0x29, 0x33), disabledButton: rgba(0x1D, 0x1F, 0x26), foreground: rgba(0xF1, 0xEF, 0xFA), disabled: rgba(0x8B, 0x88, 0x99),
			primary: rgba(0xA7, 0x8B, 0xFA), focus: rgbaA(0xA7, 0x8B, 0xFA, 0x99), hover: rgbaA(0x4A, 0x43, 0x63, 0xCC), selection: rgba(0x55, 0x3C, 0x91),
			input: rgba(0x20, 0x22, 0x2A), separator: rgba(0x3A, 0x3D, 0x49), shadow: rgbaA(0, 0, 0, 0x88),
			success: rgba(0x4A, 0xDE, 0x80), warning: rgba(0xFB, 0xBF, 0x24), failure: rgba(0xFB, 0x71, 0x85),
		}
	case "daylight":
		return productPalette{
			variant:    fyneTheme.VariantLight,
			background: rgba(0xF3, 0xF6, 0xFA), surface: rgba(0xFF, 0xFF, 0xFF), surfaceBorder: rgba(0xD5, 0xDD, 0xE9),
			button: rgba(0xE8, 0xEE, 0xF7), disabledButton: rgba(0xED, 0xF0, 0xF5), foreground: rgba(0x17, 0x20, 0x33), disabled: rgba(0x6B, 0x77, 0x8C),
			primary: rgba(0x25, 0x63, 0xEB), focus: rgbaA(0x25, 0x63, 0xEB, 0x88), hover: rgbaA(0xCF, 0xDC, 0xF2, 0xCC), selection: rgba(0xBF, 0xD3, 0xFA),
			input: rgba(0xFF, 0xFF, 0xFF), separator: rgba(0xD5, 0xDD, 0xE9), shadow: rgbaA(0x1A, 0x2B, 0x49, 0x35),
			success: rgba(0x05, 0x96, 0x69), warning: rgba(0xB4, 0x6B, 0x08), failure: rgba(0xDC, 0x26, 0x26),
		}
	default:
		return productPalette{
			variant:    fyneTheme.VariantDark,
			background: rgba(0x08, 0x0D, 0x18), surface: rgba(0x0C, 0x14, 0x22), surfaceBorder: rgba(0x25, 0x32, 0x47),
			button: rgba(0x18, 0x23, 0x35), disabledButton: rgba(0x10, 0x18, 0x27), foreground: rgba(0xE6, 0xED, 0xF7), disabled: rgba(0x78, 0x89, 0xA3),
			primary: rgba(0x4F, 0x8C, 0xFF), focus: rgbaA(0x4F, 0x8C, 0xFF, 0x99), hover: rgbaA(0x31, 0x45, 0x63, 0xCC), selection: rgba(0x1E, 0x4D, 0x9C),
			input: rgba(0x0F, 0x18, 0x28), separator: rgba(0x25, 0x32, 0x47), shadow: rgbaA(0, 0, 0, 0x80),
			success: rgba(0x2D, 0xD4, 0xA3), warning: rgba(0xFB, 0xBF, 0x24), failure: rgba(0xFB, 0x71, 0x85),
		}
	}
}

func normalizedOptionID(options []appearanceOption, id, fallback string) string {
	for _, option := range options {
		if option.ID == id {
			return id
		}
	}
	return fallback
}

func optionLabels(options []appearanceOption) []string {
	labels := make([]string, 0, len(options))
	for _, option := range options {
		labels = append(labels, option.Label)
	}
	return labels
}

func optionIDForLabel(options []appearanceOption, label, fallback string) string {
	for _, option := range options {
		if option.Label == label {
			return option.ID
		}
	}
	return fallback
}

func optionLabelForID(options []appearanceOption, id, fallback string) string {
	id = normalizedOptionID(options, id, fallback)
	for _, option := range options {
		if option.ID == id {
			return option.Label
		}
	}
	return ""
}

var (
	fontOnce      sync.Once
	fontResources map[string]fyne.Resource
)

func productFonts(fontID string) (fyne.Resource, fyne.Resource) {
	if normalizedOptionID(productFontOptions, fontID, defaultFontID) == "system" {
		return nil, nil
	}
	fontOnce.Do(loadProductFonts)
	switch normalizedOptionID(productFontOptions, fontID, defaultFontID) {
	case "heiti":
		return fontResources["heiti"], fontResources["heiti"]
	default:
		return fontResources["deng"], fontResources["dengBold"]
	}
}

func loadProductFonts() {
	fontResources = make(map[string]fyne.Resource)
	if runtime.GOOS != "windows" {
		return
	}
	fontDir := filepath.Join(`C:\Windows`, "Fonts")
	for key, fileName := range map[string]string{
		"deng": "Deng.ttf", "dengBold": "Dengb.ttf", "heiti": "simhei.ttf",
	} {
		resource, err := fyne.LoadResourceFromPath(filepath.Join(fontDir, fileName))
		if err == nil {
			fontResources[key] = resource
		}
	}
}

func rgba(r, g, b uint8) color.Color     { return color.NRGBA{R: r, G: g, B: b, A: 0xFF} }
func rgbaA(r, g, b, a uint8) color.Color { return color.NRGBA{R: r, G: g, B: b, A: a} }

package main

import (
	"testing"

	"fyne.io/fyne/v2/theme"
)

func TestAppearanceOptionFallbacks(t *testing.T) {
	if got := normalizedOptionID(productThemeOptions, "missing", defaultThemeID); got != defaultThemeID {
		t.Fatalf("theme fallback = %q", got)
	}
	if got := optionIDForLabel(productFontOptions, "现代等线", defaultFontID); got != "deng" {
		t.Fatalf("font label mapping = %q", got)
	}
	if got := optionLabelForID(productThemeOptions, "daylight", defaultThemeID); got != "云雾白" {
		t.Fatalf("theme ID mapping = %q", got)
	}
}

func TestProductPalettesAreDistinct(t *testing.T) {
	ids := []string{"midnight", "aurora", "graphite", "daylight"}
	seen := make(map[any]string)
	for _, id := range ids {
		palette := paletteForTheme(id)
		key := palette.primary
		if previous, exists := seen[key]; exists {
			t.Fatalf("themes %q and %q share primary color", previous, id)
		}
		seen[key] = id
	}
	if paletteForTheme("daylight").variant != theme.VariantLight {
		t.Fatal("daylight theme must use light variant")
	}
	if paletteForTheme("midnight").variant != theme.VariantDark {
		t.Fatal("midnight theme must use dark variant")
	}
}

func TestNewProductThemeFallsBack(t *testing.T) {
	got := newProductTheme("invalid", "invalid")
	if got == nil {
		t.Fatal("newProductTheme returned nil")
	}
	product, ok := got.(*productTheme)
	if !ok {
		t.Fatalf("theme type = %T", got)
	}
	if product.fontID != defaultFontID {
		t.Fatalf("font fallback = %q", product.fontID)
	}
}

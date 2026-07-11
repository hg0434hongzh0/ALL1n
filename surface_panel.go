package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

type productSurface struct {
	widget.BaseWidget
	title    string
	subtitle string
	content  fyne.CanvasObject
}

func newSurfacePanel(title, subtitle string, content fyne.CanvasObject) fyne.CanvasObject {
	panel := &productSurface{title: title, subtitle: subtitle, content: content}
	panel.ExtendBaseWidget(panel)
	return panel
}

func (p *productSurface) CreateRenderer() fyne.WidgetRenderer {
	border := canvas.NewRectangle(theme.Color(colorNameSurfaceBorder))
	background := canvas.NewRectangle(theme.Color(colorNameSurface))
	titleLabel := widget.NewLabelWithStyle(p.title, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	subtitleLabel := widget.NewLabel(p.subtitle)
	subtitleLabel.Importance = widget.LowImportance
	header := container.NewVBox(titleLabel, subtitleLabel, widget.NewSeparator())
	body := container.NewBorder(header, nil, nil, nil, p.content)
	root := container.NewStack(
		border,
		container.NewPadded(container.NewStack(background, container.NewPadded(body))),
	)
	return &surfaceRenderer{border: border, background: background, root: root}
}

type surfaceRenderer struct {
	border     *canvas.Rectangle
	background *canvas.Rectangle
	root       *fyne.Container
}

func (r *surfaceRenderer) Layout(size fyne.Size)        { r.root.Resize(size) }
func (r *surfaceRenderer) MinSize() fyne.Size           { return r.root.MinSize() }
func (r *surfaceRenderer) Objects() []fyne.CanvasObject { return []fyne.CanvasObject{r.root} }
func (r *surfaceRenderer) Destroy()                     {}
func (r *surfaceRenderer) Refresh() {
	r.border.FillColor = theme.Color(colorNameSurfaceBorder)
	r.background.FillColor = theme.Color(colorNameSurface)
	r.border.Refresh()
	r.background.Refresh()
	r.root.Refresh()
}

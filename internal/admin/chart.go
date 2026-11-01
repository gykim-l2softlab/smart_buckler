package admin

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"strings"
)

// column is one bar of a stacked chart. Values nil means "no data yet"
// (future hours): the slot keeps its label but draws nothing.
type column struct {
	Label  string
	Values []int
}

// chartSpec sizes a chart in viewBox units.
type chartSpec struct {
	Width, Height            float64
	Left, Right, Top, Bottom float64
	LabelEvery               int
	Class                    string
}

// stackedBars renders a stacked bar chart as inline SVG. Series are styled
// by the classes s1, s2, ... from the page stylesheet, so the chart follows
// the light and dark themes. Each column carries a native tooltip.
func stackedBars(spec chartSpec, cols []column, seriesNames []string) template.HTML {
	pw := spec.Width - spec.Left - spec.Right
	ph := spec.Height - spec.Top - spec.Bottom
	slot := pw / float64(len(cols))
	bw := math.Max(6, slot*0.62)
	maxSum := 0
	for _, c := range cols {
		sum := 0
		for _, v := range c.Values {
			sum += v
		}
		maxSum = max(maxSum, sum)
	}
	vmax := niceMax(maxSum)
	y := func(v float64) float64 { return spec.Top + ph - ph*v/float64(vmax) }

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %g %g" role="img" aria-label="%s" class="chart %s">`,
		spec.Width, spec.Height, html.EscapeString(strings.Join(seriesNames, ", ")), spec.Class)
	for i := 0; i <= 4; i++ {
		tv := float64(vmax) * float64(i) / 4
		yy := y(tv)
		fmt.Fprintf(&b, `<line class="grid" x1="%g" x2="%g" y1="%.1f" y2="%.1f"/>`, spec.Left, spec.Width-spec.Right, yy, yy)
		fmt.Fprintf(&b, `<text class="tick" x="%g" y="%.1f" text-anchor="end">%d</text>`, spec.Left-8, yy+4, int(tv))
	}
	for i, c := range cols {
		cx := spec.Left + slot*float64(i) + slot/2
		x0 := cx - bw/2
		labeled := spec.LabelEvery <= 1 || i%spec.LabelEvery == 0
		if c.Values == nil {
			if labeled {
				fmt.Fprintf(&b, `<text class="tick dim" x="%.1f" y="%g" text-anchor="middle">%s</text>`, cx, spec.Height-8, html.EscapeString(c.Label))
			}
			continue
		}
		top := -1
		for k, v := range c.Values {
			if v > 0 {
				top = k
			}
		}
		base := spec.Top + ph
		for k, v := range c.Values {
			if v <= 0 {
				continue
			}
			h := ph * float64(v) / float64(vmax)
			if k == top {
				fmt.Fprintf(&b, `<path class="s%d" d="%s"/>`, k+1, barPath(x0, base-h, bw, h, true))
			} else {
				// A 2px surface gap separates stacked segments.
				gap := math.Min(2, h/2)
				fmt.Fprintf(&b, `<path class="s%d" d="%s"/>`, k+1, barPath(x0, base-h+gap, bw, h-gap, false))
			}
			base -= h
		}
		parts := make([]string, len(c.Values))
		for k, v := range c.Values {
			parts[k] = fmt.Sprintf("%s %d", seriesNames[k], v)
		}
		fmt.Fprintf(&b, `<rect class="hit" x="%.1f" y="%g" width="%.1f" height="%g"><title>%s</title></rect>`,
			spec.Left+slot*float64(i), spec.Top, slot, ph, html.EscapeString(c.Label+": "+strings.Join(parts, ", ")))
		if labeled {
			fmt.Fprintf(&b, `<text class="tick" x="%.1f" y="%g" text-anchor="middle">%s</text>`, cx, spec.Height-8, html.EscapeString(c.Label))
		}
	}
	fmt.Fprintf(&b, `<line class="axis" x1="%g" x2="%g" y1="%g" y2="%g"/></svg>`, spec.Left, spec.Width-spec.Right, spec.Top+ph, spec.Top+ph)
	return template.HTML(b.String()) //nolint:gosec // built from numbers and escaped labels
}

// niceMax rounds v up to a value with four even gridline steps.
func niceMax(v int) int {
	if v <= 0 {
		return 4
	}
	for _, step := range []int{1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000} {
		if v <= step*4 {
			return step * 4
		}
	}
	return int(math.Ceil(float64(v)/4000)) * 4000
}

// barPath draws a bar, rounding the top corners when top is set.
func barPath(x, y, w, h float64, top bool) string {
	r := 0.0
	if top {
		r = math.Min(4, math.Min(w/2, h))
	}
	if r <= 0 {
		return fmt.Sprintf("M%.1f,%.1fV%.1fH%.1fV%.1fZ", x, y+h, y, x+w, y+h)
	}
	return fmt.Sprintf("M%.1f,%.1fV%.1fQ%.1f,%.1f %.1f,%.1fH%.1fQ%.1f,%.1f %.1f,%.1fV%.1fZ",
		x, y+h, y+r, x, y, x+r, y, x+w-r, x+w, y, x+w, y+r, y+h)
}

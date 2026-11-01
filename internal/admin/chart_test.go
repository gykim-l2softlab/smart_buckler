package admin

import (
	"strings"
	"testing"
)

func TestNiceMax(t *testing.T) {
	for _, tt := range []struct{ in, want int }{{0, 4}, {1, 4}, {4, 4}, {5, 8}, {9, 20}, {93, 100}, {101, 200}, {5000, 8000}} {
		if got := niceMax(tt.in); got != tt.want {
			t.Errorf("niceMax(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestStackedBars(t *testing.T) {
	spec := chartSpec{Width: 300, Height: 100, Left: 20, Right: 0, Top: 0, Bottom: 20, LabelEvery: 1}
	svg := string(stackedBars(spec, []column{
		{Label: "0시", Values: []int{1, 2, 0}},
		{Label: "1시", Values: []int{0, 0, 0}},
		{Label: "<b>", Values: nil},
	}, []string{"A", "B", "C"}))
	for _, want := range []string{`class="s1"`, `class="s2"`, "<title>0시: A 1, B 2, C 0</title>", `class="tick dim"`, "&lt;b&gt;"} {
		if !strings.Contains(svg, want) {
			t.Errorf("svg missing %q", want)
		}
	}
	if strings.Contains(svg, "<b>") || strings.Contains(svg, `class="s3"`) {
		t.Error("unescaped label or empty series drawn")
	}
	if n := strings.Count(svg, "<title>"); n != 2 {
		t.Errorf("%d tooltips, want 2 (no tooltip for future hours)", n)
	}
}

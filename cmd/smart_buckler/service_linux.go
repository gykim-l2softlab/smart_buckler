package main

import (
	"context"
	"os/exec"
	"strings"

	"github.com/gykim-l2softlab/smart_buckler/internal/setup"
)

const serviceHint = "sudo systemctl start " + setup.ServiceName + " 로 시작하고, 꺼진 이유는 sudo journalctl -u " + setup.ServiceName + " -n 50 으로 확인하세요."

// serviceStatus asks systemd about the smart_buckler unit. known is false
// without systemd (for example in a container) or when the unit is not installed.
func serviceStatus(ctx context.Context) (active, known bool) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false, false
	}
	unit := setup.ServiceName + ".service"
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "LoadState", "--value", unit).Output()
	if err != nil || strings.TrimSpace(string(out)) != "loaded" {
		return false, false
	}
	return exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", unit).Run() == nil, true
}

func serviceInstalled(ctx context.Context) bool {
	_, known := serviceStatus(ctx)
	return known
}

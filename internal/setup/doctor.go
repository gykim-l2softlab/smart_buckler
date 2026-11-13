package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"path/filepath"

	"github.com/gykim-l2softlab/smart_buckler/internal/config"
)

// Status is the outcome of one check.
type Status int

// Statuses, from fine to broken.
const (
	OK Status = iota
	Warn
	Fail
)

func (s Status) label() string {
	return [...]string{"정상", "주의", "문제"}[s]
}

// Check is one doctor finding.
type Check struct {
	Status Status
	Title  string
	Detail string
	// Hint is what to do about a warning or failure.
	Hint string
}

// DoctorOptions supplies the system-dependent parts of the checks. Nil
// hooks skip their check.
type DoctorOptions struct {
	ConfigPath string
	Load       func(path string) (config.Config, error)
	CheckHTTP  func(ctx context.Context, rawURL string) (int, error)
	Reachable  func(ctx context.Context, addr string) error
	// Service reports whether the installed service runs; known is false
	// when no service is installed or the service manager is unavailable.
	Service func(ctx context.Context) (active, known bool)
	// ServiceHint tells how to start the service and find why it stopped.
	ServiceHint string
	// PasswordSet reports whether the admin password is stored.
	PasswordSet func(ctx context.Context, storePath string) (bool, error)
	// StoreAccess checks that the service account can write the database.
	StoreAccess func(storePath string) error
}

// Doctor checks the installation and explains each problem.
func Doctor(ctx context.Context, o DoctorOptions) []Check {
	cfg, err := o.Load(o.ConfigPath)
	if errors.Is(err, fs.ErrNotExist) {
		return []Check{{Status: Fail, Title: "설정 파일", Detail: o.ConfigPath + " 가 없습니다.",
			Hint: "smart_buckler setup 으로 설정을 만드세요. 다른 위치에 있다면 -config 로 알려 주세요."}}
	}
	if err != nil {
		return []Check{{Status: Fail, Title: "설정 파일", Detail: err.Error(),
			Hint: "오류에 나온 항목을 고친 뒤 다시 점검하세요."}}
	}
	checks := []Check{{Status: OK, Title: "설정 파일", Detail: o.ConfigPath}}

	if o.Service != nil {
		if active, known := o.Service(ctx); known {
			if active {
				checks = append(checks, Check{Status: OK, Title: "서비스", Detail: "실행 중입니다."})
			} else {
				checks = append(checks, Check{Status: Fail, Title: "서비스", Detail: "꺼져 있습니다.", Hint: o.ServiceHint})
			}
		}
	}

	if status, err := o.CheckHTTP(ctx, cfg.Upstream); err != nil {
		checks = append(checks, Check{Status: Fail, Title: "보호할 서비스", Detail: cfg.Upstream + ": " + Explain(err),
			Hint: "보호할 서비스가 켜져 있는지, 설정의 upstream 주소가 맞는지 확인하세요."})
	} else {
		checks = append(checks, Check{Status: OK, Title: "보호할 서비스", Detail: fmt.Sprintf("%s 응답 (HTTP %d)", cfg.Upstream, status)})
	}

	checks = append(checks, proxyCheck(ctx, o, cfg))
	checks = append(checks, adminChecks(ctx, o, cfg)...)

	if o.StoreAccess != nil {
		if err := o.StoreAccess(cfg.Store.Path); err != nil {
			checks = append(checks, Check{Status: Fail, Title: "DB 파일", Detail: err.Error(),
				Hint: fmt.Sprintf("sudo chown -R %s: %s 로 소유자를 바로잡으세요.", ServiceUser, filepath.Dir(cfg.Store.Path))})
		}
	}

	if host, _, err := net.SplitHostPort(cfg.Listen); err == nil && IsLoopbackHost(host) && len(cfg.TrustedProxies) == 0 {
		checks = append(checks, Check{Status: Warn, Title: "앞단 웹 서버",
			Detail: "이 서버 안에서만 요청을 받는데 trusted_proxies가 비어 있습니다. 모든 방문자가 같은 주소로 보여 미끼 하나에 모두가 차단될 수 있습니다.",
			Hint:   `설정에 trusted_proxies: ["127.0.0.1", "::1"] 을 추가하세요.`})
	}
	return checks
}

func proxyCheck(ctx context.Context, o DoctorOptions, cfg config.Config) Check {
	addr := DialAddr(cfg.Listen)
	if err := o.Reachable(ctx, addr); err != nil {
		return Check{Status: Fail, Title: "요청 받기", Detail: addr + " 에서 요청을 받고 있지 않습니다. " + Explain(err),
			Hint: "smart_buckler가 실행 중인지 확인하세요."}
	}
	status, err := o.CheckHTTP(ctx, "http://"+addr+"/")
	switch {
	case err != nil:
		return Check{Status: Fail, Title: "요청 받기", Detail: addr + ": " + Explain(err)}
	case status == http.StatusBadGateway:
		return Check{Status: Fail, Title: "요청 받기", Detail: "요청은 받지만 보호할 서비스로 넘기지 못합니다 (HTTP 502).",
			Hint: "위의 '보호할 서비스' 항목을 먼저 해결하세요."}
	case status == http.StatusForbidden:
		return Check{Status: Warn, Title: "요청 받기", Detail: "점검 요청이 막혔습니다 (HTTP 403). 이 서버 주소가 차단됐거나 WAF가 막았을 수 있습니다.",
			Hint: "관리 화면의 차단 목록을 확인하세요."}
	}
	return Check{Status: OK, Title: "요청 받기", Detail: fmt.Sprintf("%s 에서 받아 보호할 서비스로 넘깁니다 (HTTP %d)", addr, status)}
}

func adminChecks(ctx context.Context, o DoctorOptions, cfg config.Config) []Check {
	if !cfg.Admin.Enabled {
		return []Check{{Status: OK, Title: "관리 화면", Detail: "꺼져 있습니다 (admin.enabled: false)."}}
	}
	var checks []Check
	addr := DialAddr(cfg.Admin.Listen)
	if err := o.Reachable(ctx, addr); err != nil {
		checks = append(checks, Check{Status: Fail, Title: "관리 화면", Detail: addr + " 에 열려 있지 않습니다. " + Explain(err),
			Hint: "smart_buckler가 실행 중인지 확인하세요."})
	} else {
		checks = append(checks, Check{Status: OK, Title: "관리 화면", Detail: addr + " 에 열려 있습니다."})
	}
	if host, _, err := net.SplitHostPort(cfg.Admin.Listen); err == nil && !IsLoopbackHost(host) {
		checks = append(checks, Check{Status: Warn, Title: "관리 화면 노출",
			Detail: cfg.Admin.Listen + " 는 이 서버 밖에서도 접속됩니다. 암호화 없이 비밀번호가 오갑니다.",
			Hint:   "admin.listen을 " + AdminListen + " 로 두고 SSH 터널이나 원격 데스크톱으로 접속하세요."})
	}
	if o.PasswordSet != nil {
		set, err := o.PasswordSet(ctx, cfg.Store.Path)
		switch {
		case err != nil:
			checks = append(checks, Check{Status: Warn, Title: "관리자 비밀번호", Detail: "확인하지 못했습니다: " + err.Error()})
		case !set:
			checks = append(checks, Check{Status: Warn, Title: "관리자 비밀번호", Detail: "아직 없어서 관리 화면이 닫혀 있습니다.",
				Hint: "smart_buckler admin-password 로 정하세요."})
		default:
			checks = append(checks, Check{Status: OK, Title: "관리자 비밀번호", Detail: "정해져 있습니다."})
		}
	}
	return checks
}

// Report prints the checks and returns how many failed.
func Report(w io.Writer, checks []Check) int {
	var n [3]int
	for _, c := range checks {
		n[c.Status]++
		fmt.Fprintf(w, "[%s] %s: %s\n", c.Status.label(), c.Title, c.Detail)
		if c.Status != OK && c.Hint != "" {
			fmt.Fprintf(w, "       → %s\n", c.Hint)
		}
	}
	fmt.Fprintf(w, "\n결과: 정상 %d, 주의 %d, 문제 %d\n", n[OK], n[Warn], n[Fail])
	return n[Fail]
}

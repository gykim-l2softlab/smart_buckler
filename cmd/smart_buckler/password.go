package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gykim-l2softlab/smart_buckler/internal/admin"
	"github.com/gykim-l2softlab/smart_buckler/internal/config"
)

// setAdminPassword sets the admin UI password. On a terminal it asks twice
// with echo off; otherwise it reads one line from stdin, for scripts.
func setAdminPassword(ctx context.Context, configPath, ownerName string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	pw, err := promptPassword(os.Stdin, bufio.NewReader(os.Stdin))
	if err != nil {
		return err
	}
	own, err := ownerFor(ownerName, cfg.Store.Path)
	if err != nil {
		return err
	}
	if err := savePassword(ctx, cfg.Store.Path, pw, own); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "관리자 비밀번호를 저장했습니다. 이전에 로그인한 세션은 모두 끝납니다.")
	if !cfg.Admin.Enabled {
		fmt.Fprintln(os.Stderr, "관리 화면이 꺼져 있습니다. 설정에서 admin.enabled를 true로 바꾸세요.")
	}
	return nil
}

// promptPassword reads the password from in. Off a terminal it reads one
// line through r, which must be the reader already wrapping in so buffered
// input is not lost.
func promptPassword(in *os.File, r *bufio.Reader) (string, error) {
	if fi, err := in.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return readLine(r)
	}
	fmt.Fprintf(os.Stderr, "새 관리자 비밀번호 (%d자 이상): ", admin.MinPasswordLength)
	pw, err := readHidden(in)
	if err != nil {
		return "", err
	}
	if len([]rune(pw)) < admin.MinPasswordLength {
		return "", fmt.Errorf("비밀번호는 %d자 이상이어야 합니다", admin.MinPasswordLength)
	}
	fmt.Fprint(os.Stderr, "한 번 더 입력: ")
	again, err := readHidden(in)
	if err != nil {
		return "", err
	}
	if pw != again {
		return "", errors.New("두 비밀번호가 다릅니다")
	}
	return pw, nil
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

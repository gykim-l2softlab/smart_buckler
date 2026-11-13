//go:build !windows

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// owner is the service account files are handed to. A nil owner leaves
// ownership alone.
type owner struct{ uid, gid int }

// serviceOwner returns the named account when running as root and the
// account exists, as on a server prepared by the installer. Otherwise files
// keep the current user, which suits development.
func serviceOwner(name string) (*owner, error) {
	if name == "" || os.Geteuid() != 0 {
		return nil, nil
	}
	u, err := user.Lookup(name)
	var unknown user.UnknownUserError
	if errors.As(err, &unknown) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, err
	}
	return &owner{uid: uid, gid: gid}, nil
}

// ownerWarning explains why files stay with root when setup runs as root
// for the installed layout but the service account does not exist yet.
func ownerWarning(name string, own *owner) string {
	if own != nil || os.Geteuid() != 0 {
		return ""
	}
	return fmt.Sprintf("[주의] %s 계정이 없어 파일을 root 소유로 둡니다. 서비스를 다른 계정으로 돌린다면 그 계정이 설정 파일을 읽고 DB 폴더에 쓸 수 있게 하세요.\n", name)
}

// own gives the existing paths to the account.
func (o *owner) own(paths ...string) error {
	if o == nil {
		return nil
	}
	for _, p := range paths {
		if err := os.Lchown(p, o.uid, o.gid); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// group keeps path owned by root and lets the account's group read it.
func (o *owner) group(path string) error {
	if o == nil {
		return nil
	}
	return os.Lchown(path, 0, o.gid)
}

// storeAccess checks that the database and its directory belong to the
// service account, when one exists.
func storeAccess(name string) func(string) error {
	return func(path string) error {
		u, err := user.Lookup(name)
		if err != nil {
			return nil // no service account: a development setup
		}
		for _, p := range append([]string{filepath.Dir(path)}, storeFiles(path)...) {
			fi, err := os.Stat(p)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return err
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && strconv.FormatUint(uint64(st.Uid), 10) != u.Uid {
				return fmt.Errorf("%s 의 소유자가 %s 가 아니어서 서비스가 기록하지 못할 수 있습니다", p, name)
			}
		}
		return nil
	}
}

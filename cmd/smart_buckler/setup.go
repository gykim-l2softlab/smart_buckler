package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/gykim-l2softlab/smart_buckler/internal/admin"
	"github.com/gykim-l2softlab/smart_buckler/internal/config"
	"github.com/gykim-l2softlab/smart_buckler/internal/setup"
	"github.com/gykim-l2softlab/smart_buckler/internal/store"
)

// errReported means the command already explained the failure; main only
// sets the exit status.
var errReported = errors.New("reported")

func defaultPaths() setup.Paths { return setup.DefaultPaths(runtime.GOOS, os.Getenv) }

// ownerFor returns the service account to hand files to, but only for the
// installed layout: files at a custom path are never re-owned.
func ownerFor(name, storePath string) (*owner, error) {
	if storePath != defaultPaths().Store {
		return nil, nil
	}
	return serviceOwner(name)
}

// runSetup asks for the essentials and writes the configuration.
func runSetup(ctx context.Context, configPath, ownerName string, force bool) error {
	paths := setup.Paths{Config: configPath, Store: defaultPaths().Store}
	if configPath != defaultPaths().Config {
		store, err := filepath.Abs(filepath.Join(filepath.Dir(configPath), setup.DBName))
		if err != nil {
			return err
		}
		paths.Store = store
	}
	if _, err := os.Stat(configPath); err == nil && !force {
		return fmt.Errorf("설정 파일이 이미 있습니다: %s\n  상태 점검: smart_buckler doctor\n  처음부터 다시 만들기: smart_buckler setup -force", configPath)
	}
	own, err := ownerFor(ownerName, paths.Store)
	if err != nil {
		return err
	}
	if paths.Store == defaultPaths().Store {
		fmt.Print(ownerWarning(ownerName, own))
	}
	configDir, storeDir := filepath.Dir(paths.Config), filepath.Dir(paths.Store)
	for _, dir := range []string{configDir, storeDir} {
		if err := probeWritable(dir); err != nil {
			return fmt.Errorf("%s 에 쓸 수 없습니다. 관리자 권한(sudo)으로 실행하세요: %w", dir, err)
		}
	}
	// The service account must reach its config and own its data directory.
	if err := own.group(configDir); err != nil {
		return err
	}
	if err := own.own(storeDir); err != nil {
		return err
	}

	in := bufio.NewReader(os.Stdin)
	w := &setup.Wizard{
		Prompt:      setup.NewPrompter(in, os.Stdout),
		Out:         os.Stdout,
		Paths:       paths,
		Timezone:    setup.DetectTimezone(os.Getenv, os.Readlink),
		CheckHTTP:   setup.CheckHTTP,
		PortFree:    setup.PortFree,
		Reachable:   setup.Reachable,
		WriteConfig: func(path string, data []byte) error { return writeConfig(path, data, own) },
		ReadPassword: func() (string, error) {
			return promptPassword(os.Stdin, in)
		},
		SavePassword: func(ctx context.Context, storePath, pw string) error {
			return savePassword(ctx, storePath, pw, own)
		},
	}
	o, err := w.Run(ctx)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Print(setup.NextSteps(o, setup.NextInfo{
		GOOS:             runtime.GOOS,
		ConfigPath:       configPath,
		ServiceInstalled: serviceInstalled(ctx),
		SSHUser:          sshUser(),
		ServerIP:         setup.OutboundIP(),
	}))
	return nil
}

// runDoctor checks the installation and exits non-zero on any failure.
func runDoctor(ctx context.Context, configPath, ownerName string) error {
	fmt.Printf("smart_buckler %s 상태 점검\n\n", version())
	checks := setup.Doctor(ctx, setup.DoctorOptions{
		ConfigPath:  configPath,
		Load:        config.Load,
		CheckHTTP:   setup.CheckHTTP,
		Reachable:   setup.Reachable,
		Service:     serviceStatus,
		ServiceHint: serviceHint,
		PasswordSet: func(ctx context.Context, storePath string) (bool, error) {
			return passwordSet(ctx, storePath, ownerName)
		},
		StoreAccess: storeAccess(ownerName),
	})
	if setup.Report(os.Stdout, checks) > 0 {
		return errReported
	}
	return nil
}

// passwordSet reports whether the admin password is stored. A missing
// database means the service never ran, so no password is set; it is not
// created here.
func passwordSet(ctx context.Context, storePath, ownerName string) (bool, error) {
	if _, err := os.Stat(storePath); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	own, err := ownerFor(ownerName, storePath)
	if err != nil {
		return false, err
	}
	st, err := store.Open(ctx, storePath)
	if err != nil {
		return false, err
	}
	v, err := st.GetSecret(ctx, admin.PasswordSecret)
	_ = st.Close()
	// Opening as root may have created WAL files the service cannot write.
	if oerr := own.own(storeFiles(storePath)...); oerr != nil && err == nil {
		err = oerr
	}
	return v != nil, err
}

// savePassword hashes pw and stores it, leaving the database owned by the
// service account.
func savePassword(ctx context.Context, storePath, pw string, own *owner) error {
	hash, err := admin.HashPassword(pw)
	if err != nil {
		return err
	}
	dir := filepath.Dir(storePath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := own.own(dir); err != nil {
		return err
	}
	st, err := store.Open(ctx, storePath)
	if err != nil {
		return err
	}
	err = st.SetSecret(ctx, admin.PasswordSecret, []byte(hash))
	if cerr := st.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return own.own(storeFiles(storePath)...)
}

// writeConfig replaces path atomically with data, readable by the service
// account's group only: the file can hold notify tokens and API keys.
func writeConfig(path string, data []byte, own *owner) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".smart_buckler-*.yaml")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename
	if err := f.Chmod(0o640); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := own.group(tmp); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// probeWritable creates dir if needed and checks that files can be created in it.
func probeWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".smart_buckler-probe-*")
	if err != nil {
		return err
	}
	_ = f.Close()
	return os.Remove(f.Name())
}

func storeFiles(path string) []string { return []string{path, path + "-wal", path + "-shm"} }

// sshUser is the login to suggest for the SSH tunnel: the user behind sudo.
func sshUser() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u := os.Getenv("USER"); u != "" && u != "root" {
		return u
	}
	return ""
}

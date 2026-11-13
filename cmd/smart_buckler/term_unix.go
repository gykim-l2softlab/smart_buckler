//go:build linux || darwin

package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// readHidden reads a line from the terminal with echo turned off.
func readHidden(f *os.File) (string, error) {
	fd := f.Fd()
	var old syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlGetTermios, uintptr(unsafe.Pointer(&old))); e != 0 {
		return "", fmt.Errorf("read terminal settings: %w", e)
	}
	quiet := old
	quiet.Lflag &^= syscall.ECHO
	quiet.Lflag |= syscall.ICANON | syscall.ISIG
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlSetTermios, uintptr(unsafe.Pointer(&quiet))); e != 0 {
		return "", fmt.Errorf("turn off echo: %w", e)
	}
	defer func() {
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlSetTermios, uintptr(unsafe.Pointer(&old)))
		fmt.Fprintln(os.Stderr)
	}()
	return readLine(bufio.NewReader(f))
}

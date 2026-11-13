//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
)

func readHidden(*os.File) (string, error) {
	return "", errors.New("hidden input is not supported on this system; pipe the password on stdin instead")
}

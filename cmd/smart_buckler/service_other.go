//go:build !linux

package main

import "context"

const serviceHint = ""

// serviceStatus reports no installed service; service management on other
// systems is not supported yet.
func serviceStatus(context.Context) (active, known bool) { return false, false }

func serviceInstalled(context.Context) bool { return false }

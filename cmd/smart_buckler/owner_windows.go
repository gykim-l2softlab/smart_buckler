package main

// owner is a no-op on Windows; file permissions there are set by the
// installer.
type owner struct{}

func serviceOwner(string) (*owner, error) { return nil, nil }

func ownerWarning(string, *owner) string { return "" }

func (o *owner) own(...string) error { return nil }

func (o *owner) group(string) error { return nil }

func storeAccess(string) func(string) error { return nil }

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWritePEMReplacesTheFileAs0644WithNoTemporaryFileLeft(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "proxy.crt")

	if err := writePEM(path, "old"); err != nil {
		t.Fatal(err)
	}
	if err := writePEM(path, "new"); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "new" {
		t.Fatalf("content = %q, want %q", b, "new")
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want only the certificate", len(entries))
	}
}

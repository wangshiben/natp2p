package logx

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSplitFilesAndSizeArchive(t *testing.T) {
	directory := t.TempDir()
	previousLevel := GetLevel()
	SetLevel(LevelDebug)
	t.Cleanup(func() { SetLevel(previousLevel) })
	if err := Configure(Config{
		Directory: directory, MaxSizeBytes: 220, RotateInterval: time.Hour,
		Retention: time.Hour, Console: false, IncludeErrorStack: false,
	}); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 6; index++ {
		Infof("info payload index=%d value=%s", index, strings.Repeat("i", 80))
	}
	Warnf("recoverable warning")
	Errorf("isolated failure: %s", "broken stream")
	if err := Close(); err != nil {
		t.Fatal(err)
	}
	warning, err := os.ReadFile(filepath.Join(directory, "warn.log"))
	if err != nil || !bytes.Contains(warning, []byte("recoverable warning")) || bytes.Contains(warning, []byte("isolated failure")) {
		t.Fatalf("unexpected warning log: %q err=%v", warning, err)
	}
	errorLog, err := os.ReadFile(filepath.Join(directory, "error.log"))
	if err != nil || !bytes.Contains(errorLog, []byte("isolated failure")) {
		t.Fatalf("unexpected error log: %q err=%v", errorLog, err)
	}
	archives, err := filepath.Glob(filepath.Join(directory, "archive", "info-*.tar.gz"))
	if err != nil || len(archives) == 0 {
		t.Fatalf("info archive missing: %v err=%v", archives, err)
	}
	if !bytes.Contains(readArchive(t, archives[0]), []byte("info payload")) {
		t.Fatal("info archive does not contain the rotated log")
	}
	resetDefaultSink(t)
}

func TestTimeArchive(t *testing.T) {
	directory := t.TempDir()
	if err := Configure(Config{
		Directory: directory, MaxSizeBytes: 1 << 20, RotateInterval: 30 * time.Millisecond,
		Console: false, IncludeErrorStack: false,
	}); err != nil {
		t.Fatal(err)
	}
	Warnf("time archive")
	deadline := time.Now().Add(2 * time.Second)
	for {
		archives, err := filepath.Glob(filepath.Join(directory, "archive", "warn-*.tar.gz"))
		if err != nil {
			t.Fatal(err)
		}
		if len(archives) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("time archive was not created")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := Close(); err != nil {
		t.Fatal(err)
	}
	resetDefaultSink(t)
}

func resetDefaultSink(t *testing.T) {
	t.Helper()
	if err := Configure(DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	log.SetOutput(os.Stderr)
}

func readArchive(t *testing.T, path string) []byte {
	t.Helper()
	archiveFile, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archiveFile.Close()
	gzipReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		t.Fatal(err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	if _, err := tarReader.Next(); err != nil {
		t.Fatal(err)
	}
	encoded, err := io.ReadAll(tarReader)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

package logx

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (sink *splitSink) createArchive(task archiveTask) error {
	info, err := os.Stat(task.source)
	if err != nil {
		return fmt.Errorf("logx: inspect pending %s archive: %w", task.level, err)
	}
	baseName := strings.TrimSuffix(filepath.Base(task.source), ".log")
	destination := filepath.Join(sink.archiveDirectory, baseName+".tar.gz")
	temporary, err := os.CreateTemp(sink.archiveDirectory, ".archive-*.tmp")
	if err != nil {
		return fmt.Errorf("logx: create %s archive: %w", task.level, err)
	}
	temporaryName := temporary.Name()
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		os.Remove(temporaryName)
		return fmt.Errorf("logx: protect %s archive: %w", task.level, err)
	}
	source, err := os.Open(task.source)
	if err != nil {
		temporary.Close()
		os.Remove(temporaryName)
		return fmt.Errorf("logx: open pending %s archive: %w", task.level, err)
	}
	gzipWriter := gzip.NewWriter(temporary)
	tarWriter := tar.NewWriter(gzipWriter)
	header := &tar.Header{
		Name: filepath.Base(task.source), Mode: 0o600, Size: info.Size(),
		ModTime: info.ModTime().UTC(), AccessTime: time.Time{}, ChangeTime: time.Time{},
	}
	writeErr := tarWriter.WriteHeader(header)
	if writeErr == nil {
		_, writeErr = io.Copy(tarWriter, source)
	}
	closeErrors := []error{source.Close(), tarWriter.Close(), gzipWriter.Close(), temporary.Sync(), temporary.Close()}
	archiveErr := errors.Join(closeErrors...)
	if writeErr != nil {
		archiveErr = errors.Join(fmt.Errorf("logx: write %s archive: %w", task.level, writeErr), archiveErr)
	}
	if archiveErr != nil {
		os.Remove(temporaryName)
		return archiveErr
	}
	if err := os.Rename(temporaryName, destination); err != nil {
		os.Remove(temporaryName)
		return fmt.Errorf("logx: publish %s archive: %w", task.level, err)
	}
	if err := os.Remove(task.source); err != nil {
		return fmt.Errorf("logx: remove packed %s log: %w", task.level, err)
	}
	return sink.removeExpiredArchives(time.Now().UTC())
}

func (sink *splitSink) removeExpiredArchives(now time.Time) error {
	if sink.retention <= 0 {
		return nil
	}
	entries, err := os.ReadDir(sink.archiveDirectory)
	if err != nil {
		return fmt.Errorf("logx: scan archives for retention: %w", err)
	}
	cutoff := now.Add(-sink.retention)
	var removalErrors []error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tar.gz") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			removalErrors = append(removalErrors, fmt.Errorf("logx: inspect archive %s: %w", entry.Name(), err))
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(sink.archiveDirectory, entry.Name())
			if err := os.Remove(path); err != nil {
				removalErrors = append(removalErrors, fmt.Errorf("logx: remove expired archive %s: %w", path, err))
			}
		}
	}
	return errors.Join(removalErrors...)
}

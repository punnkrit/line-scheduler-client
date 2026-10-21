package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const maxArchive = 64 << 20
const maxExpanded = 128 << 20

// ErrDurability means replacement succeeded but persistence across a crash
// could not be confirmed. Callers must not describe this as an unchanged file.
var ErrDurability = errors.New("the update was installed, but its durability could not be confirmed; run line version to check the installed version")

// Install replaces a recognized standalone installation. The caller must hold
// the watch and session locks throughout this operation. Downloads are pinned
// to the checked release, never a moving /latest/download URL.
func (s *Service) Install(ctx context.Context, p Plan) error {
	if s.distribution == "fork" {
		return errors.New("automatic updates are disabled for this fork; review and rebuild from your source checkout")
	}
	if !p.CanSelfUpdate || p.CurrentVersion != s.current || versionStatus(s.current, p.LatestVersion) != "update_available" ||
		(s.goos != "linux" && s.goos != "darwin") || !supportedPlatform(s.goos, s.arch) {
		return errors.New("automatic update is unavailable; run line update --check for instructions")
	}
	if err := s.verifyTarget(p.Executable); err != nil {
		return err
	}
	before, err := os.Lstat(p.Executable)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("the executable is not a regular, unprivileged file; use your original installation method")
	}
	if p.original == nil || !sameExecutable(p.original, before) {
		return errors.New("the installed executable changed since the update check; run line update again")
	}
	// Staging beside the destination guarantees the rename stays on one filesystem
	// and finds permission problems before downloading any release assets.
	staged, err := os.CreateTemp(filepath.Dir(p.Executable), ".line-update-*")
	if err != nil {
		return errors.New("cannot write to the installation directory; use your original installation method")
	}
	defer os.Remove(staged.Name())
	defer staged.Close()

	archive := archiveName(s.goos, s.arch)
	resp, err := s.get(ctx, assetURL(p.LatestVersion, "SHA256SUMS.txt"))
	if err != nil {
		return err
	}
	checksums, readErr := io.ReadAll(io.LimitReader(resp.Body, maxMetadata+1))
	resp.Body.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if readErr != nil || len(checksums) > maxMetadata {
		return errors.New("could not read release checksums; no files were changed")
	}
	expected, err := checksumFor(checksums, archive)
	if err != nil {
		return err
	}

	// Keep compressed downloads on disk and bounded rather than buffering them in
	// memory. Only the selected executable is extracted from the verified archive.
	download, err := os.CreateTemp(filepath.Dir(p.Executable), ".line-download-*")
	if err != nil {
		return errors.New("could not stage the release download; no files were changed")
	}
	defer os.Remove(download.Name())
	defer download.Close()
	resp, err = s.get(ctx, assetURL(p.LatestVersion, archive))
	if err != nil {
		return err
	}
	hash := sha256.New()
	n, readErr := io.Copy(io.MultiWriter(download, hash), io.LimitReader(resp.Body, maxArchive+1))
	resp.Body.Close()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if readErr != nil || n > maxArchive {
		return errors.New("release download failed or exceeded the size limit; no files were changed")
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("release checksum verification failed; no files were changed")
	}
	if _, err := download.Seek(0, io.SeekStart); err != nil {
		return errors.New("could not read the staged download; no files were changed")
	}
	if err := extractExecutable(ctx, download, staged); err != nil {
		return err
	}
	if err := staged.Chmod(before.Mode().Perm()); err != nil {
		return errors.New("could not set executable permissions; no files were changed")
	}
	if err := staged.Sync(); err != nil {
		return errors.New("could not save the staged executable; no files were changed")
	}
	if err := staged.Close(); err != nil {
		return errors.New("could not close the staged executable; no files were changed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.verifyTarget(p.Executable); err != nil {
		return err
	}
	after, err := os.Lstat(p.Executable)
	if err != nil || !sameExecutable(before, after) {
		return errors.New("the installed executable changed during the update; run line update again")
	}
	if err := os.Rename(staged.Name(), p.Executable); err != nil {
		return errors.New("could not replace the executable; no files were changed")
	}
	dir, err := os.Open(filepath.Dir(p.Executable))
	if err != nil {
		return ErrDurability
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return ErrDurability
	}
	return nil
}

func sameExecutable(before, after os.FileInfo) bool {
	return os.SameFile(before, after) && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) && before.Mode() == after.Mode()
}

func (s *Service) verifyTarget(target string) error {
	path, err := s.executable()
	if err != nil {
		return errors.New("could not locate the installed executable; no files were changed")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil || path != target || s.installation(path) != "standalone" {
		return errors.New("installation ownership changed or could not be verified; run line update --check")
	}
	return nil
}

func extractExecutable(ctx context.Context, archive io.Reader, dst io.Writer) error {
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return errors.New("invalid release archive; no files were changed")
	}
	defer gz.Close()
	limited := &io.LimitedReader{R: gz, N: maxExpanded + 1}
	reader := tar.NewReader(limited)
	found := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := reader.Next()
		if limited.N <= 0 {
			return errors.New("release archive exceeds the expanded size limit; no files were changed")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("invalid release archive; no files were changed")
		}
		if h.Name != "line" && h.Name != "./line" {
			continue
		}
		if found || h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > maxExpanded {
			return errors.New("invalid executable in release archive; no files were changed")
		}
		if _, err := io.Copy(dst, reader); err != nil {
			return errors.New("could not stage the executable; no files were changed")
		}
		found = true
	}
	if !found {
		return errors.New("release archive has no executable; no files were changed")
	}
	return nil
}

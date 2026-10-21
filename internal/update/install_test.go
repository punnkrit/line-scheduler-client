//go:build darwin || linux

package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeArchive(t *testing.T, headers []*tar.Header, content string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, h := range headers {
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(content))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func installFixture(t *testing.T, archive []byte, checksum string, hook func()) (*Service, Plan) {
	t.Helper()
	s := testService(t)
	s.client = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case latestAPI:
			return response(200, metadata("v0.3.1")), nil
		case assetURL("v0.3.1", "SHA256SUMS.txt"):
			if checksum == "" {
				checksum = fmt.Sprintf("%x", sha256.Sum256(archive))
			}
			return response(200, checksum+"  "+archiveName("linux", "amd64")), nil
		case assetURL("v0.3.1", archiveName("linux", "amd64")):
			if hook != nil {
				hook()
			}
			return response(200, string(archive)), nil
		default:
			t.Fatalf("unexpected download: %s", r.URL)
			return nil, nil
		}
	})}
	p, err := s.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func assertOnlyInstallation(t *testing.T, path string) {
	t.Helper()
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Name() != "line" && f.Name() != receiptName {
			t.Errorf("staging file leaked: %s", f.Name())
		}
	}
}

func TestInstallVerifiedRelease(t *testing.T) {
	archive := makeArchive(t, []*tar.Header{{Name: "./line", Typeflag: tar.TypeReg, Mode: 0755}, {Name: "../ignored", Typeflag: tar.TypeReg}}, "new executable")
	s, p := installFixture(t, archive, "", nil)
	if err := s.Install(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p.Executable)
	if err != nil || string(got) != "new executable" {
		t.Fatal("replacement failed", err)
	}
	info, err := os.Stat(p.Executable)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatal("executable permissions changed")
	}
	if s.installation(p.Executable) != "standalone" {
		t.Fatal("lost installation ownership")
	}
	assertOnlyInstallation(t, p.Executable)
}

func TestFailedVerificationPreservesExecutable(t *testing.T) {
	for _, tt := range []struct {
		name     string
		headers  []*tar.Header
		checksum string
	}{
		{"checksum", []*tar.Header{{Name: "line", Typeflag: tar.TypeReg}}, strings.Repeat("0", 64)},
		{"missing", []*tar.Header{{Name: "../line", Typeflag: tar.TypeReg}}, ""},
		{"symlink", []*tar.Header{{Name: "line", Typeflag: tar.TypeSymlink, Linkname: "/tmp/other"}}, ""},
		{"duplicate", []*tar.Header{{Name: "line", Typeflag: tar.TypeReg}, {Name: "./line", Typeflag: tar.TypeReg}}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, p := installFixture(t, makeArchive(t, tt.headers, "bad executable"), tt.checksum, nil)
			if err := s.Install(context.Background(), p); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			got, _ := os.ReadFile(p.Executable)
			if string(got) != "original executable" {
				t.Fatal("failed update damaged original")
			}
			assertOnlyInstallation(t, p.Executable)
		})
	}
}

func TestCancelledUpdatePreservesExecutable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, p := installFixture(t, makeArchive(t, []*tar.Header{{Name: "line", Typeflag: tar.TypeReg}}, "new executable"), "", cancel)
	if err := s.Install(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p.Executable)
	if string(got) != "original executable" {
		t.Fatal("cancelled update replaced executable")
	}
	assertOnlyInstallation(t, p.Executable)
}

func TestChangedInstallationIsNotOverwritten(t *testing.T) {
	for _, duringDownload := range []bool{false, true} {
		t.Run(fmt.Sprint(duringDownload), func(t *testing.T) {
			var path string
			change := func() {
				if err := os.WriteFile(path, []byte("concurrent source build"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			var hook func()
			if duringDownload {
				hook = change
			}
			s, p := installFixture(t, makeArchive(t, []*tar.Header{{Name: "line", Typeflag: tar.TypeReg}}, "new executable"), "", hook)
			path = p.Executable
			if !duringDownload {
				change()
			}
			if err := s.Install(context.Background(), p); err == nil {
				t.Fatal("concurrent installation replaced")
			}
			got, _ := os.ReadFile(path)
			if string(got) != "concurrent source build" {
				t.Fatal("overwrote concurrent installation")
			}
			assertOnlyInstallation(t, path)
		})
	}
}

func TestInstallRejectsDowngradesAndUnsupportedOwnership(t *testing.T) {
	for _, change := range []func(*Service, *Plan){
		func(s *Service, p *Plan) { p.LatestVersion = "v0.2.0" },
		func(s *Service, p *Plan) { p.LatestVersion = "v0.3.0" },
		func(s *Service, p *Plan) { p.LatestVersion = "../../other" },
		func(s *Service, p *Plan) { s.distribution = "source" },
		func(s *Service, p *Plan) { s.goos = "windows" },
		func(s *Service, p *Plan) { p.CanSelfUpdate = false },
	} {
		s, p := installFixture(t, nil, "", nil)
		change(s, &p)
		s.client = &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
			t.Fatal("unsafe plan made a download request")
			return nil, nil
		})}
		if err := s.Install(context.Background(), p); err == nil {
			t.Fatal("unsafe plan accepted")
		}
	}
}

func TestForkReleaseInstallerRefusesWithoutDownload(t *testing.T) {
	fixture := t.TempDir()
	bin := filepath.Join(fixture, "tools")
	installDir := filepath.Join(fixture, "custom install")
	networkMarker := filepath.Join(fixture, "network-invoked")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"curl", "wget"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nprintf invoked > \"$UPDATE_NETWORK_MARKER\"\nexit 99\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "../../scripts/install-release.sh")
	cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "LINE_CLI_INSTALL_DIR="+installDir, "UPDATE_NETWORK_MARKER="+networkMarker, "LINE_CLI_DOWNLOAD_BASE=https://example.invalid/releases")
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "Build from source") {
		t.Fatalf("installer did not refuse with build guidance: %v\n%s", err, output)
	}
	for _, path := range []string{networkMarker, installDir} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("installer downloaded or modified files: %s %v", path, err)
		}
	}
}

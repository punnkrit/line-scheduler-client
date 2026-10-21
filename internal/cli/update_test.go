package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kongesque/line-cli/internal/update"
)

type fakeUpdater struct {
	plan                 update.Plan
	checks, installs     int
	checkErr, installErr error
	onInstall            func()
}

func (f *fakeUpdater) Check(context.Context) (update.Plan, error) {
	f.checks++
	return f.plan, f.checkErr
}
func (f *fakeUpdater) Install(context.Context, update.Plan) error {
	f.installs++
	if f.onInstall != nil {
		f.onInstall()
	}
	return f.installErr
}

func updateApp() (*App, *fakeUpdater, *bytes.Buffer, *bytes.Buffer) {
	out, diagnostics := new(bytes.Buffer), new(bytes.Buffer)
	f := &fakeUpdater{plan: update.Plan{CurrentVersion: "v0.3.0", LatestVersion: "v0.3.1", Status: "update_available",
		Installation: "standalone", CanSelfUpdate: true, Executable: "/example/line", ReleaseURL: "https://github.com/kongesque/line-cli/releases/tag/v0.3.1", Instructions: "Run line update to install this release."}}
	// No manager, credential store, or LINE API is needed by this command.
	a := &App{Out: out, Err: diagnostics, Updater: f}
	return a, f, out, diagnostics
}

func TestForkUpdateShowsSourceGuidanceWithoutLocks(t *testing.T) {
	for _, args := range [][]string{nil, {"--check"}, {"--json"}, {"--check", "--json"}} {
		out, diagnostics := new(bytes.Buffer), new(bytes.Buffer)
		a := &App{Out: out, Err: diagnostics, Version: "v0.5.0", Distribution: "fork"}
		a.Lock = func() (func(), error) { t.Fatal("fork update opened session"); return nil, nil }
		a.WatchLock = func() (func(), error) { t.Fatal("fork update acquired watcher lock"); return nil, nil }
		if err := a.Run(append([]string{"update"}, args...)); err != nil {
			t.Fatal(err)
		}
		if diagnostics.Len() != 0 || !strings.Contains(out.String(), "managed from source") || strings.Contains(out.String(), "An update is available") {
			t.Fatalf("unexpected output: %q %q", out.String(), diagnostics.String())
		}
		if strings.Contains(strings.Join(args, " "), "--json") {
			var p update.Plan
			if err := json.Unmarshal(out.Bytes(), &p); err != nil || p.Status != "managed" || p.CanSelfUpdate {
				t.Fatalf("unexpected JSON plan: %+v %v", p, err)
			}
		}
	}
}

func TestUpdateValidationNeverChecksOrLocks(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"--unknown"}, {"extra"}, {"--check", "extra"}} {
		a, f, _, _ := updateApp()
		a.Lock = func() (func(), error) { t.Fatal("opened session"); return nil, nil }
		_ = a.Run(append([]string{"update"}, args...))
		if f.checks != 0 || f.installs != 0 {
			t.Fatal("invalid args accessed updater")
		}
	}
}

func TestUpdateCheckAndManualFlowsNeverLock(t *testing.T) {
	for _, tt := range []struct {
		args      []string
		status    string
		automatic bool
		want      string
	}{
		{[]string{"--check"}, "update_available", true, "No changes made"},
		{nil, "up_to_date", true, "You're up to date"},
		{nil, "ahead", true, "newer than"},
		{nil, "unknown_version", false, "cannot be compared"},
		{nil, "update_available", false, "brew upgrade line-cli"},
	} {
		a, f, out, _ := updateApp()
		f.plan.Status, f.plan.CanSelfUpdate = tt.status, tt.automatic
		if !tt.automatic {
			f.plan.Installation, f.plan.UpgradeCommand = "homebrew", "brew upgrade line-cli"
		}
		a.Lock = func() (func(), error) { t.Fatal("opened session"); return nil, nil }
		a.WatchLock = a.Lock
		if err := a.Run(append([]string{"update"}, tt.args...)); err != nil {
			t.Fatal(err)
		}
		if f.installs != 0 || !strings.Contains(out.String(), tt.want) {
			t.Fatalf("unexpected flow: %s", out)
		}
	}
}

func TestUpdateJSONAndLockLifecycle(t *testing.T) {
	for _, installErr := range []error{nil, errors.New("checksum failed"), update.ErrDurability} {
		a, f, out, diagnostics := updateApp()
		watchHeld, sessionHeld := false, false
		a.WatchLock = func() (func(), error) { watchHeld = true; return func() { watchHeld = false }, nil }
		a.Lock = func() (func(), error) {
			if !watchHeld {
				t.Fatal("wrong lock order")
			}
			sessionHeld = true
			return func() { sessionHeld = false }, nil
		}
		f.onInstall = func() {
			if !watchHeld || !sessionHeld {
				t.Fatal("installation without both locks")
			}
		}
		f.installErr = installErr
		err := a.Run([]string{"update", "--json"})
		if !errors.Is(err, installErr) {
			t.Fatal(err)
		}
		var p update.Plan
		if err := json.Unmarshal(out.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		want := "updated"
		if installErr != nil {
			want = "failed"
		}
		if errors.Is(installErr, update.ErrDurability) {
			want = "updated_unconfirmed"
		}
		if p.Status != want || diagnostics.Len() != 0 || sessionHeld || watchHeld || f.installs != 1 {
			t.Fatalf("bad result: %+v", p)
		}
	}
}

func TestUpdateBusyNeverInstalls(t *testing.T) {
	for _, busyWatch := range []bool{false, true} {
		a, f, out, _ := updateApp()
		watchHeld := false
		a.WatchLock = func() (func(), error) {
			if busyWatch {
				return nil, errors.New("busy")
			}
			watchHeld = true
			return func() { watchHeld = false }, nil
		}
		a.Lock = func() (func(), error) { return nil, errors.New("busy") }
		if err := a.Run([]string{"update"}); err == nil {
			t.Fatal("busy update succeeded")
		}
		if f.installs != 0 || watchHeld || strings.Contains(out.String(), "Updated to") {
			t.Fatal("busy update installed or leaked lock")
		}
	}
}

func TestUpdateCheckJSONIsReadOnly(t *testing.T) {
	a, f, out, diagnostics := updateApp()
	if err := a.Run([]string{"update", "--check", "--json"}); err != nil {
		t.Fatal(err)
	}
	var p update.Plan
	if err := json.Unmarshal(out.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Status != "update_available" || f.installs != 0 || diagnostics.Len() != 0 {
		t.Fatal("check mutated or polluted JSON")
	}
}

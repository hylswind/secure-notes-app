package volume

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type exitErr struct{ code int }

func (e exitErr) Error() string { return "exit" }
func (e exitErr) ExitCode() int { return e.code }

type fake struct {
	calls    []string
	lsblk    string
	isLuks   bool
	unlockOK bool
}

func (f *fake) run(_ context.Context, name string, args ...string) (string, error) {
	base := filepath.Base(name)
	f.calls = append(f.calls, base+" "+strings.Join(args, " "))
	switch base {
	case "lsblk":
		return f.lsblk, nil
	case "cryptsetup":
		if args[0] == "isLuks" {
			if f.isLuks {
				return "", nil
			}
			return "", exitErr{1}
		}
	case "systemd-cryptsetup":
		if !f.unlockOK {
			return "TPM2 policy mismatch", exitErr{1}
		}
	}
	return "", nil
}

func (f *fake) called(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func disk(name, fstype string, children bool) string {
	c := ""
	if children {
		c = `,"children":[{"name":"` + name + `p1"}]`
	}
	return `{"name":"` + name + `","path":"/dev/` + name + `","type":"disk","fstype":` + qs(fstype) + `,"model":"Amazon Elastic Block Store","mountpoints":[null]` + c + `}`
}

func qs(s string) string {
	if s == "" {
		return "null"
	}
	return `"` + s + `"`
}

func lsblk(devs ...string) string {
	return `{"blockdevices":[` + strings.Join(devs, ",") + `]}`
}

func setup(t *testing.T, f *fake, mounted bool, env map[string]string) (*Manager, *[]string) {
	dir := t.TempDir()
	var logs []string
	return &Manager{
		Run:        f.run,
		Getenv:     func(k string) string { return env[k] },
		IsMounted:  func(string) bool { return mounted },
		Chown:      func(string) error { return nil },
		Log:        func(s string) { logs = append(logs, s) },
		MountPoint: filepath.Join(dir, "data"),
		KeyDir:     dir,
		StatePath:  filepath.Join(dir, "state"),
		Cryptsetup: "/usr/lib/systemd/systemd-cryptsetup",
	}, &logs
}

func TestFreshDevice(t *testing.T) {
	f := &fake{lsblk: lsblk(disk("nvme0n1", "", true), disk("nvme1n1", "", false)), unlockOK: true}
	m, logs := setup(t, f, false, nil)
	st, err := m.Ensure(context.Background())
	if err != nil || st != StateEnrolled {
		t.Fatalf("st=%s err=%v", st, err)
	}
	if len(*logs) != 1 || (*logs)[0] != "ENROLLED /dev/nvme1n1" {
		t.Fatalf("logs %v", *logs)
	}
	for _, p := range []string{"cryptsetup luksFormat --type luks2", "systemd-cryptenroll --unlock-key-file=", "systemd-cryptsetup attach", "mkfs.ext4", "mount /dev/mapper"} {
		if !f.called(p) {
			t.Errorf("missing call %q in %v", p, f.calls)
		}
	}
	if !f.called("systemd-cryptenroll --unlock-key-file=") || !strings.Contains(strings.Join(f.calls, "\n"), "--tpm2-pcrs=4+12") ||
		!strings.Contains(strings.Join(f.calls, "\n"), "--wipe-slot=password") {
		t.Errorf("enroll calls: %v", f.calls)
	}
	ents, _ := os.ReadDir(filepath.Dir(m.StatePath))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "secure-notes-key-") {
			t.Error("key file left behind")
		}
	}
}

func TestExistingLUKSUnlocks(t *testing.T) {
	f := &fake{lsblk: lsblk(disk("nvme0n1", "", true), disk("nvme1n1", "crypto_LUKS", false)), isLuks: true, unlockOK: true}
	m, logs := setup(t, f, false, nil)
	st, err := m.Ensure(context.Background())
	if err != nil || st != StateUnlocked || (*logs)[0] != "UNLOCKED /dev/nvme1n1" {
		t.Fatalf("st=%s err=%v logs=%v", st, err, *logs)
	}
	if f.called("cryptsetup luksFormat") || f.called("mkfs") || f.called("systemd-cryptenroll") {
		t.Fatalf("existing LUKS device must not be formatted: %v", f.calls)
	}
}

func TestTPMRefusal(t *testing.T) {
	f := &fake{lsblk: lsblk(disk("nvme1n1", "crypto_LUKS", false)), isLuks: true, unlockOK: false}
	m, logs := setup(t, f, false, nil)
	_, err := m.Ensure(context.Background())
	var r *Refusal
	if !errors.As(err, &r) || !strings.Contains(r.Reason, "TPM2 policy mismatch") {
		t.Fatalf("err=%v", err)
	}
	if !strings.HasPrefix((*logs)[0], "REFUSED: ") {
		t.Fatalf("logs %v", *logs)
	}
	if f.called("cryptsetup luksFormat") || f.called("mkfs") || f.called("mount") {
		t.Fatalf("must not touch device: %v", f.calls)
	}
	b, _ := os.ReadFile(m.StatePath)
	if !strings.HasPrefix(string(b), "REFUSED") {
		t.Fatalf("state %q", b)
	}
}

func TestZeroAndTwoCandidates(t *testing.T) {
	f := &fake{lsblk: lsblk(disk("nvme0n1", "", true))}
	m, _ := setup(t, f, false, nil)
	if _, err := m.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("zero: %v", err)
	}
	f = &fake{lsblk: lsblk(disk("nvme1n1", "", false), disk("nvme2n1", "", false))}
	m, _ = setup(t, f, false, nil)
	if _, err := m.Ensure(context.Background()); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("two: %v", err)
	}
	if f.called("cryptsetup") {
		t.Fatal("must not touch anything")
	}
}

func TestAlreadyMounted(t *testing.T) {
	f := &fake{}
	m, logs := setup(t, f, true, nil)
	st, err := m.Ensure(context.Background())
	if err != nil || st != StateUnlocked || (*logs)[0] != "ALREADY MOUNTED" || len(f.calls) != 0 {
		t.Fatalf("st=%s err=%v logs=%v calls=%v", st, err, *logs, f.calls)
	}
}

func TestDataDeviceOverride(t *testing.T) {
	f := &fake{isLuks: true, unlockOK: true}
	m, logs := setup(t, f, false, map[string]string{"DATA_DEVICE": "/dev/nvme9n1"})
	if _, err := m.Ensure(context.Background()); err != nil || (*logs)[0] != "UNLOCKED /dev/nvme9n1" {
		t.Fatalf("err=%v logs=%v", err, *logs)
	}
	if f.called("lsblk") {
		t.Fatal("lsblk should not run")
	}
}

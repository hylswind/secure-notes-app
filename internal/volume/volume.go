// Package volume implements the privileged data-volume logic: discovery of the
// extra EBS device, LUKS2 formatting with a TPM2-sealed key, unlocking and mounting.
package volume

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	MapperName = "secure-notes-data"
	StateFile  = "/run/secure-notes-volume.state"

	StateUnlocked = "UNLOCKED"
	StateEnrolled = "ENROLLED"
	StateRefused  = "REFUSED"
)

// Runner runs an external command and returns its combined output.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// ExecRunner runs real commands.
func ExecRunner(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// Manager holds everything the data-volume logic depends on, so tests can inject fakes.
type Manager struct {
	Run        Runner
	Getenv     func(string) string
	IsMounted  func(path string) bool
	Chown      func(path string) error
	Log        func(string)
	MountPoint string // /data
	KeyDir     string // /run
	StatePath  string
	Cryptsetup string // path of systemd-cryptsetup helper
}

// New returns a Manager wired to the real system.
func New(log func(string)) *Manager {
	return &Manager{
		Run:        ExecRunner,
		Getenv:     os.Getenv,
		IsMounted:  isMountPoint,
		Chown:      chownApp,
		Log:        log,
		MountPoint: "/data",
		KeyDir:     "/run",
		StatePath:  StateFile,
		Cryptsetup: "/usr/lib/systemd/systemd-cryptsetup",
	}
}

func chownApp(path string) error {
	u, err := user.Lookup("app")
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return os.Chown(path, uid, gid)
}

func isMountPoint(path string) bool {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 4 && f[4] == path {
			return true
		}
	}
	return false
}

// Refusal is returned when the volume must not be used.
type Refusal struct{ Reason string }

func (r *Refusal) Error() string { return "REFUSED: " + r.Reason }

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

func refuse(format string, a ...any) error {
	return &Refusal{Reason: oneLine(fmt.Sprintf(format, a...))}
}

type lsblkOut struct {
	Blockdevices []lsblkDev `json:"blockdevices"`
}

type lsblkDev struct {
	Name        string            `json:"name"`
	Path        string            `json:"path"`
	Type        string            `json:"type"`
	FSType      string            `json:"fstype"`
	Model       string            `json:"model"`
	Mountpoints []*string         `json:"mountpoints"`
	Mountpoint  *string           `json:"mountpoint"`
	Children    []json.RawMessage `json:"children"`
}

func (d lsblkDev) mounted() bool {
	if d.Mountpoint != nil && *d.Mountpoint != "" {
		return true
	}
	for _, m := range d.Mountpoints {
		if m != nil && *m != "" {
			return true
		}
	}
	return false
}

// Discover finds the single unused EBS NVMe disk.
func (m *Manager) Discover(ctx context.Context) (string, error) {
	out, err := m.Run(ctx, "lsblk", "--json", "-o", "NAME,PATH,TYPE,FSTYPE,MODEL,MOUNTPOINTS")
	if err != nil {
		return "", refuse("lsblk failed: %s", out)
	}
	var parsed lsblkOut
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return "", refuse("cannot parse lsblk output: %v", err)
	}
	var cands []string
	for _, d := range parsed.Blockdevices {
		if d.Type != "disk" || !strings.HasPrefix(d.Name, "nvme") {
			continue
		}
		if d.Model != "" && !strings.Contains(d.Model, "Elastic Block Store") {
			continue
		}
		if len(d.Children) > 0 || d.mounted() {
			continue
		}
		if d.FSType != "" && d.FSType != "crypto_LUKS" {
			continue
		}
		p := d.Path
		if p == "" {
			p = "/dev/" + d.Name
		}
		cands = append(cands, p)
	}
	switch len(cands) {
	case 0:
		return "", refuse("no candidate data device found")
	case 1:
		return cands[0], nil
	}
	return "", refuse("more than one candidate data device: %s", strings.Join(cands, ","))
}

type exitCoder interface{ ExitCode() int }

func (m *Manager) isLUKS(ctx context.Context, dev string) (bool, error) {
	out, err := m.Run(ctx, "cryptsetup", "isLuks", dev)
	if err == nil {
		return true, nil
	}
	var ec exitCoder
	if errors.As(err, &ec) && ec.ExitCode() == 1 {
		return false, nil
	}
	return false, refuse("cannot determine whether %s is LUKS: %s %v", dev, out, err)
}

func (m *Manager) writeState(state, reason string) {
	if m.StatePath == "" {
		return
	}
	_ = os.WriteFile(m.StatePath, []byte(state+"\n"+reason+"\n"), 0o644)
}

func (m *Manager) open(ctx context.Context, dev string) error {
	out, err := m.Run(ctx, m.Cryptsetup, "attach", MapperName, dev, "-", "tpm2-device=auto")
	if err != nil {
		return refuse("TPM2 unlock failed: %s", firstNonEmpty(out, err.Error()))
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func (m *Manager) mount(ctx context.Context) error {
	if err := os.MkdirAll(m.MountPoint, 0o755); err != nil {
		return refuse("cannot create %s: %v", m.MountPoint, err)
	}
	out, err := m.Run(ctx, "mount", "/dev/mapper/"+MapperName, m.MountPoint)
	if err != nil {
		return refuse("mount failed: %s", firstNonEmpty(out, err.Error()))
	}
	return nil
}

func (m *Manager) finishMount() error {
	if m.Chown != nil {
		if err := m.Chown(m.MountPoint); err != nil {
			return refuse("chown %s: %v", m.MountPoint, err)
		}
	}
	return os.Chmod(m.MountPoint, 0o700)
}

// Ensure makes /data available. It returns the resulting state.
func (m *Manager) Ensure(ctx context.Context) (state string, err error) {
	defer func() {
		var r *Refusal
		if errors.As(err, &r) {
			m.writeState(StateRefused, r.Reason)
			m.Log(r.Error())
		}
	}()
	if m.IsMounted(m.MountPoint) {
		m.Log("ALREADY MOUNTED")
		if _, e := os.Stat(m.StatePath); e != nil {
			m.writeState(StateUnlocked, "already mounted")
		}
		return StateUnlocked, nil
	}
	dev := m.Getenv("DATA_DEVICE")
	if dev == "" {
		if dev, err = m.Discover(ctx); err != nil {
			return "", err
		}
	}
	luks, err := m.isLUKS(ctx, dev)
	if err != nil {
		return "", err
	}
	if luks {
		if err = m.open(ctx, dev); err != nil {
			return "", err
		}
		if err = m.mount(ctx); err != nil {
			return "", err
		}
		if err = m.finishMount(); err != nil {
			return "", err
		}
		m.writeState(StateUnlocked, "")
		m.Log("UNLOCKED " + dev)
		return StateUnlocked, nil
	}
	if err = m.format(ctx, dev); err != nil {
		return "", err
	}
	m.writeState(StateEnrolled, "")
	m.Log("ENROLLED " + dev)
	return StateEnrolled, nil
}

func (m *Manager) format(ctx context.Context, dev string) (err error) {
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return refuse("random: %v", err)
	}
	f, err := os.CreateTemp(m.KeyDir, "secure-notes-key-")
	if err != nil {
		return refuse("cannot create key file: %v", err)
	}
	kf := f.Name()
	defer os.Remove(kf)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return refuse("chmod key file: %v", err)
	}
	_, werr := f.Write(key)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		return refuse("cannot write key file")
	}
	steps := [][]string{
		{"cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--key-file=" + kf, dev},
		{"systemd-cryptenroll", "--unlock-key-file=" + kf, "--tpm2-device=auto", "--tpm2-pcrs=4+12", dev},
		{"systemd-cryptenroll", "--unlock-key-file=" + kf, "--wipe-slot=password", dev},
	}
	for _, s := range steps {
		if out, e := m.Run(ctx, s[0], s[1:]...); e != nil {
			return refuse("%s failed: %s", filepath.Base(s[0]), firstNonEmpty(out, e.Error()))
		}
	}
	if err := m.open(ctx, dev); err != nil {
		return err
	}
	if out, e := m.Run(ctx, "mkfs.ext4", "-q", "/dev/mapper/"+MapperName); e != nil {
		return refuse("mkfs.ext4 failed: %s", firstNonEmpty(out, e.Error()))
	}
	if err := m.mount(ctx); err != nil {
		return err
	}
	return m.finishMount()
}

// RelaxPrivilegedPorts lets the unprivileged app user bind ports 80 and 443.
// The platform's unit for the app may not grant CAP_NET_BIND_SERVICE.
func RelaxPrivilegedPorts(log func(string)) {
	const p = "/proc/sys/net/ipv4/ip_unprivileged_port_start"
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	if v, _ := strconv.Atoi(strings.TrimSpace(string(b))); v <= 80 {
		return
	}
	if err := os.WriteFile(p, []byte("80\n"), 0o644); err != nil {
		log("could not lower ip_unprivileged_port_start: " + err.Error())
	}
}

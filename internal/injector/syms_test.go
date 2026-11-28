//go:build linux && amd64

package injector

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// T5: load base must be start - fileOffset, not the raw start of the r-xp segment.
// The r-xp segment of libc typically starts at a non-zero file offset (e.g. 0x24000),
// so using its start directly shifts every symbol by that offset.
func TestParseLoadBase_Libc(t *testing.T) {
	mapsData := strings.Join([]string{
		"7f5a46000000-7f5a46024000 r--p 00000000 00:1d 3427  /usr/lib/libc.so.6",
		"7f5a46024000-7f5a4619f000 r-xp 00024000 00:1d 3427  /usr/lib/libc.so.6",
		"7f5a4619f000-7f5a46215000 r--p 0019f000 00:1d 3427  /usr/lib/libc.so.6",
		"7f5a46219000-7f5a4621b000 rw-p 00218000 00:1d 3427  /usr/lib/libc.so.6",
		"",
	}, "\n")

	base, path, err := parseLoadBase(mapsData)
	assert.NoError(t, err)
	assert.Equal(t, uintptr(0x7f5a46000000), base, "load base must be start-offset of the first segment")
	assert.Equal(t, "/usr/lib/libc.so.6", path)
}

func TestParseLoadBase_NotFound(t *testing.T) {
	mapsData := "555555554000-555555555000 r-xp 00000000 08:01 1 /usr/bin/sleep\n\n"
	_, _, err := parseLoadBase(mapsData)
	assert.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "libc")
}

// T25: matching must be exact on the basename, not a substring of the whole path.
func TestIsLibcPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/usr/lib/libc.so.6", true},
		{"/lib/x86_64-linux-gnu/libc.so", true},
		{"/lib/libc-2.28.so", true},
		{"/usr/lib/libcrypt.so.1", false},
		{"/usr/lib/libc.software.so", false},
		{"/usr/lib/libdl.so.2", false},
		{"/usr/lib/libm.so.6", false},
		{"[heap]", false},
	}
	for _, c := range cases {
		assert.Equalf(t, c.want, isLibcPath(c.path), "isLibcPath(%q)", c.path)
	}
}

// T24: version suffixes must be stripped when comparing symbol names.
func TestSymbolBaseName(t *testing.T) {
	assert.Equal(t, "dlopen", symbolBaseName("dlopen"))
	assert.Equal(t, "dlopen", symbolBaseName("dlopen@@GLIBC_2.34"))
	assert.Equal(t, "dlopen", symbolBaseName("dlopen@GLIBC_2.2.5"))
}

// T24: findSymbolOffset must skip SHN_UNDEF symbols (Value==0) and non-FUNC symbols,
// returning the real function vaddr.
func TestFindSymbolOffset_DlopenDefined(t *testing.T) {
	libc := findLibcOnDisk(t)
	off, err := findSymbolOffset(libc, "dlopen")
	assert.NoError(t, err)
	assert.NotZero(t, off, "dlopen vaddr must not be zero (undef would be 0)")
}

func TestFindSymbolOffset_MissingSymbol(t *testing.T) {
	libc := findLibcOnDisk(t)
	_, err := findSymbolOffset(libc, "definitely_not_a_real_symbol_xyz")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "definitely_not_a_real_symbol_xyz")
}

// End-to-end invariant: for a live process, the resolved dlopen address must fall inside
// an r-xp mapping of libc in that process's maps. With the old base-without-offset bug the
// address is shifted by the file offset and lands outside the executable segment.
func TestFindDlopenAddr_InExecutableMapping(t *testing.T) {
	t.Parallel()
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("sleep not found: %v", err)
	}
	cmd := exec.Command(sleepPath, "30")
	assert.NoError(t, cmd.Start())
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	time.Sleep(50 * time.Millisecond)

	addr, err := FindDlopenAddr(cmd.Process.Pid)
	assert.NoError(t, err)
	assert.NotZero(t, addr)

	mapsData, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/maps")
	if err != nil {
		t.Skipf("cannot read maps: %v", err)
	}
	assert.True(t, addrInExecMapping(string(mapsData), addr),
		"dlopen addr 0x%x must lie within an r-xp libc mapping", addr)
}

func TestFindDlopenAddr_InvalidPID(t *testing.T) {
	_, err := FindDlopenAddr(999999)
	assert.Error(t, err, "FindDlopenAddr must fail for invalid PID")
}

// --- test helpers ---

// findLibcOnDisk returns a libc ELF to inspect, or skips the test.
func findLibcOnDisk(t *testing.T) string {
	t.Helper()
	mapsData, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Skipf("cannot read /proc/self/maps: %v", err)
	}
	_, path, err := parseLoadBase(string(mapsData))
	if err != nil {
		t.Skipf("no libc in self maps: %v", err)
	}
	return path
}

// addrInExecMapping reports whether addr falls within any r-xp file mapping in maps.
func addrInExecMapping(mapsData string, addr uintptr) bool {
	for _, line := range strings.Split(mapsData, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[1] != "r-xp" {
			continue
		}
		var start, end uintptr
		if _, err := fmt.Sscanf(fields[0], "%x-%x", &start, &end); err != nil {
			continue
		}
		if addr >= start && addr < end {
			return true
		}
	}
	return false
}

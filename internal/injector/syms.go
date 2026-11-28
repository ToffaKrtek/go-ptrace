//go:build linux && amd64

package injector

import (
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// FindDlopenAddr resolves the runtime address of dlopen in the target process.
// It reads the target's memory map to locate libc's load base and then adds the
// dlopen symbol's virtual address taken from the libc ELF on disk.
func FindDlopenAddr(pid int) (uintptr, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", mapsPath, err)
	}

	baseAddr, elfPath, err := parseLoadBase(string(data))
	if err != nil {
		return 0, err
	}

	symOffset, err := findSymbolOffset(elfPath, "dlopen")
	if err != nil {
		return 0, fmt.Errorf("find dlopen symbol: %w", err)
	}

	return baseAddr + uintptr(symOffset), nil
}

// parseLoadBase finds the libc mapping in a /proc/pid/maps blob and returns its ELF
// load base and on-disk path.
//
// T5: the load base is (segment start - segment file offset), which is constant across
// all segments of one ELF. The old code returned the raw start of the r-xp segment, but
// that segment begins at a non-zero file offset (e.g. 0x24000 for modern glibc), so every
// resolved symbol was shifted by that offset and pointed into read-only data instead of
// the function.
func parseLoadBase(mapsData string) (uintptr, string, error) {
	var base uintptr
	var libPath string
	var found bool

	for _, line := range strings.Split(mapsData, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := fields[5]
		if !isLibcPath(path) {
			continue
		}

		var start, end, offset uintptr
		if _, err := fmt.Sscanf(fields[0], "%x-%x", &start, &end); err != nil {
			continue
		}
		if _, err := fmt.Sscanf(fields[2], "%x", &offset); err != nil {
			continue
		}

		// Segments appear in ascending start order; the first libc segment wins.
		if !found {
			base = start - offset
			libPath = path
			found = true
		}
	}

	if !found {
		return 0, "", fmt.Errorf("no libc mapping found in maps (target may be statically linked)")
	}
	return base, libPath, nil
}

// isLibcPath matches a maps pathname against the glibc shared object by basename.
// T25: it must not use a loose substring match, otherwise libcrypt.so.1,
// libc.software.so, etc. would be mistaken for libc. Accepted forms are the modern
// "libc.so[.VER]" and the legacy "libc-<version>.so".
func isLibcPath(path string) bool {
	base := filepath.Base(path)
	if base == "libc.so" || strings.HasPrefix(base, "libc.so.") {
		return true
	}
	if strings.HasPrefix(base, "libc-") && strings.HasSuffix(base, ".so") {
		return true
	}
	return false
}

// symbolBaseName strips the ELF version suffix (e.g. "dlopen@@GLIBC_2.34" -> "dlopen").
// T24.
func symbolBaseName(name string) string {
	if i := strings.IndexByte(name, '@'); i >= 0 {
		return name[:i]
	}
	return name
}

// findSymbolOffset returns the virtual address of a function symbol in an ELF file.
//
// T24: it skips undefined symbols (SHN_UNDEF, whose Value is 0) and non-function symbols,
// so that a dangling reference does not silently resolve to address 0 and produce a
// confusing "dlopen address must not be zero" error downstream.
func findSymbolOffset(elfPath, symbolName string) (uint64, error) {
	f, err := elf.Open(elfPath)
	if err != nil {
		return 0, fmt.Errorf("open ELF %s: %w", elfPath, err)
	}
	defer f.Close()

	// Prefer dynamic symbols: that is what the linker actually resolves at runtime and
	// what libc.so.6 carries even when .symtab has been stripped.
	syms, err := f.DynamicSymbols()
	if err != nil || len(syms) == 0 {
		syms, err = f.Symbols()
		if err != nil && len(syms) == 0 {
			return 0, fmt.Errorf("read symbols from %s: %w", elfPath, err)
		}
	}

	for _, sym := range syms {
		if symbolBaseName(sym.Name) != symbolName {
			continue
		}
		if sym.Section == elf.SHN_UNDEF {
			continue
		}
		if sym.Info&0xf != uint8(elf.STT_FUNC) {
			continue
		}
		if sym.Value == 0 {
			continue
		}
		return sym.Value, nil
	}

	return 0, fmt.Errorf("function symbol %s not found in %s", symbolName, elfPath)
}

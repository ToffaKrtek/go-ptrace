package injector

import (
	"debug/elf"
	"fmt"
	"os"
	"strings"
)

func FindDlopenAddr(pid int) (uintptr, error) {
	baseAddr, elfPath, err := findLibcBase(pid)
	if err != nil {
		return 0, fmt.Errorf("find libc base: %w", err)
	}

	symOffset, err := findSymbolOffset(elfPath, "dlopen")
	if err != nil {
		return 0, fmt.Errorf("find dlopen symbol: %w", err)
	}

	return baseAddr + uintptr(symOffset), nil
}

func findLibcBase(pid int) (uintptr, string, error) {
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return 0, "", fmt.Errorf("read maps: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		path := fields[5]
		if !strings.Contains(path, "libc.so") {
			continue
		}

		// Parse address range
		var start, end uintptr
		_, err := fmt.Sscanf(fields[0], "%x-%x", &start, &end)
		if err != nil {
			continue
		}

		// Look for readable+executable mapping (r-xp)
		perms := fields[1]
		if perms != "r-xp" {
			continue
		}

		return start, path, nil
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		path := fields[5]
		if !strings.Contains(path, "libdl.so") {
			continue
		}

		var start, end uintptr
		_, err := fmt.Sscanf(fields[0], "%x-%x", &start, &end)
		if err != nil {
			continue
		}

		perms := fields[1]
		if perms != "r-xp" {
			continue
		}

		return start, path, nil
	}

	return 0, "", fmt.Errorf("no libc.so or libdl.so found in /proc/%d/maps", pid)
}

func findSymbolOffset(elfPath, symbolName string) (uint64, error) {
	f, err := elf.Open(elfPath)
	if err != nil {
		return 0, fmt.Errorf("open ELF: %w", err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		// Try dynamic symbols
		syms, err = f.DynamicSymbols()
		if err != nil {
			return 0, fmt.Errorf("read symbols: %w", err)
		}
	}

	for _, sym := range syms {
		if sym.Name == symbolName {
			return sym.Value, nil
		}
	}

	return 0, fmt.Errorf("symbol %s not found in %s", symbolName, elfPath)
}

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	pid, libPath, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		fmt.Fprintf(os.Stderr, "Usage: %s --pid <PID> --so <path/to/library.so>\n", os.Args[0])
		os.Exit(1)
	}

	fmt.Printf("Injecting %s into process %d...\n", libPath, pid)

	err = inject(pid, libPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Injection failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Injection successful!")
}

func parseArgs(args []string) (int, string, error) {
	var pid int
	var libPath string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--pid":
			if i+1 >= len(args) {
				return 0, "", fmt.Errorf("--pid requires a value")
			}
			i++
			p, err := strconv.Atoi(args[i])
			if err != nil {
				return 0, "", fmt.Errorf("invalid pid '%s': must be a positive integer", args[i])
			}
			if p <= 0 {
				return 0, "", fmt.Errorf("pid must be a positive integer, got %d", p)
			}
			pid = p

		case "--so":
			if i+1 >= len(args) {
				return 0, "", fmt.Errorf("--so requires a value")
			}
			i++
			libPath = args[i]

		case "--help", "-h":
			fmt.Printf("Usage: go-ptrace --pid <PID> --so <path/to/library.so>\n")
			fmt.Println("\nInject a shared library into a target process by PID.")
			os.Exit(0)

		default:
			if strings.HasPrefix(args[i], "--") {
				return 0, "", fmt.Errorf("unknown flag: %s", args[i])
			}
		}
	}

	if pid == 0 {
		return 0, "", fmt.Errorf("--pid is required")
	}
	if libPath == "" {
		return 0, "", fmt.Errorf("--so is required")
	}

	// Check that the .so file exists
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		return pid, libPath, fmt.Errorf("library file not found: %s", libPath)
	}

	return pid, libPath, nil
}

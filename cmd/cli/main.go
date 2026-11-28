package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// defaultTimeout mirrors injector.DefaultWaitTimeout; it is duplicated here so the CLI
// stays buildable on platforms where the injector package is excluded by build tags.
const defaultTimeout = 30 * time.Second

// options is the parsed command line.
type options struct {
	pid     int
	libPath string
	dryRun  bool
	verbose bool
	timeout time.Duration
}

// injectOptions carries the CLI knobs that reach the injection engine. It is declared
// here, outside the platform-tagged files, so both implementations share one type.
type injectOptions struct {
	// Timeout bounds every wait for a ptrace event (T17).
	Timeout time.Duration
	// Verbose streams each pipeline stage to stderr (T32).
	Verbose bool
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		usage(os.Stderr)
		os.Exit(1)
	}

	if opts.dryRun {
		if err := dryRun(opts.pid, opts.libPath, opts.timeout); err != nil {
			fmt.Fprintf(os.Stderr, "Dry run failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Printf("Injecting %s into process %d...\n", opts.libPath, opts.pid)

	err = inject(opts.pid, opts.libPath, injectOptions{Timeout: opts.timeout, Verbose: opts.verbose})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Injection failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Injection successful!")
}

func usage(w io.Writer) {
	fmt.Fprintf(w, "Usage: %s --pid <PID> --so <path/to/library.so> [options]\n", os.Args[0])
	fmt.Fprintln(w, "\nInject a shared library into a target process by PID.")
	fmt.Fprintln(w, "\nOptions:")
	fmt.Fprintln(w, "  --pid <PID>        target process id (required)")
	fmt.Fprintln(w, "  --so <path>        absolute path of the .so to inject (required)")
	fmt.Fprintln(w, "  --dry-run          validate the plan without attaching to the target")
	fmt.Fprintln(w, "  --verbose          print every pipeline stage to stderr")
	fmt.Fprintf(w, "  --timeout <dur>    per-step wait timeout, e.g. 5s (default %s)\n", defaultTimeout)
	fmt.Fprintln(w, "  --help, -h         show this help")
}

func parseArgs(args []string) (*options, error) {
	opts := &options{timeout: defaultTimeout}

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--pid":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--pid requires a value")
			}
			i++
			p, err := strconv.Atoi(args[i])
			if err != nil {
				return nil, fmt.Errorf("invalid pid '%s': must be a positive integer", args[i])
			}
			if p <= 0 {
				return nil, fmt.Errorf("pid must be a positive integer, got %d", p)
			}
			opts.pid = p

		case "--so":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--so requires a value")
			}
			i++
			opts.libPath = args[i]

		case "--timeout":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--timeout requires a value")
			}
			i++
			d, err := time.ParseDuration(args[i])
			if err != nil {
				return nil, fmt.Errorf("invalid --timeout '%s': %w", args[i], err)
			}
			if d <= 0 {
				return nil, fmt.Errorf("--timeout must be positive, got %s", d)
			}
			opts.timeout = d

		case "--dry-run":
			opts.dryRun = true

		case "--verbose", "-v":
			opts.verbose = true

		case "--help", "-h":
			usage(os.Stdout)
			os.Exit(0)

		default:
			if strings.HasPrefix(args[i], "--") {
				return nil, fmt.Errorf("unknown flag: %s", args[i])
			}
		}
	}

	if opts.pid == 0 {
		return nil, errors.New("--pid is required")
	}
	if opts.libPath == "" {
		return nil, errors.New("--so is required")
	}
	// The target resolves the path inside its own mount namespace and cwd, so a relative
	// path is ambiguous; reject it before we get anywhere near ptrace.
	if !strings.HasPrefix(opts.libPath, "/") {
		return nil, fmt.Errorf("library path must be absolute (it is resolved in the target's namespace): %q", opts.libPath)
	}

	// Check that the .so file exists.
	if _, err := os.Stat(opts.libPath); os.IsNotExist(err) {
		return opts, fmt.Errorf("library file not found: %s", opts.libPath)
	}

	return opts, nil
}

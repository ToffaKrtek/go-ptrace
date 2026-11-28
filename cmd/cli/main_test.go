package main

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// existingFile returns a path that always exists, to satisfy the --so existence check.
func existingFile(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return exe
}

func TestParseArgs_NoArgs(t *testing.T) {
	_, err := parseArgs(nil)
	assert.Error(t, err)
}

func TestParseArgs_PIDFlagOnly(t *testing.T) {
	_, err := parseArgs([]string{"--pid", "1234"})
	assert.Error(t, err) // missing --so
}

func TestParseArgs_SoFlagOnly(t *testing.T) {
	_, err := parseArgs([]string{"--so", "/tmp/test.so"})
	assert.Error(t, err) // missing --pid
}

func TestParseArgs_BothFlags(t *testing.T) {
	opts, err := parseArgs([]string{"--pid", "5678", "--so", "/tmp/lib.so"})
	assert.Error(t, err) // file not found
	if assert.NotNil(t, opts) {
		assert.Equal(t, 5678, opts.pid)
		assert.Equal(t, "/tmp/lib.so", opts.libPath)
	}
}

func TestParseArgs_InvalidPID(t *testing.T) {
	_, err := parseArgs([]string{"--pid", "abc", "--so", "/tmp/lib.so"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pid")
}

func TestParseArgs_SoNotExists(t *testing.T) {
	_, err := parseArgs([]string{"--pid", "1234", "--so", "/nonexistent/lib.so"})
	assert.Error(t, err)
}

func TestParseArgs_PIDZero(t *testing.T) {
	_, err := parseArgs([]string{"--pid", "0", "--so", "/tmp/lib.so"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pid")
}

func TestParseArgs_NegativePID(t *testing.T) {
	_, err := parseArgs([]string{"--pid", "-1", "--so", "/tmp/lib.so"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pid")
}

func TestParseArgs_UnknownFlag(t *testing.T) {
	_, err := parseArgs([]string{"--pid", "1", "--so", "/tmp/lib.so", "--wat"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown flag")
}

// A relative --so is ambiguous inside the target's namespace, so the CLI rejects it.
func TestParseArgs_RelativePathRejected(t *testing.T) {
	_, err := parseArgs([]string{"--pid", "1", "--so", "lib/hooklib.so"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "absolute")
}

func TestParseArgs_Defaults(t *testing.T) {
	opts, err := parseArgs([]string{"--pid", "1", "--so", existingFile(t)})
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, defaultTimeout, opts.timeout)
	assert.False(t, opts.dryRun)
	assert.False(t, opts.verbose)
}

// T32: --dry-run and --verbose.
func TestParseArgs_DryRunAndVerbose(t *testing.T) {
	opts, err := parseArgs([]string{"--pid", "1", "--so", existingFile(t), "--dry-run", "--verbose"})
	if !assert.NoError(t, err) {
		return
	}
	assert.True(t, opts.dryRun)
	assert.True(t, opts.verbose)
}

func TestParseArgs_VerboseShortFlag(t *testing.T) {
	opts, err := parseArgs([]string{"--pid", "1", "--so", existingFile(t), "-v"})
	if !assert.NoError(t, err) {
		return
	}
	assert.True(t, opts.verbose)
	assert.False(t, opts.dryRun, "-v must not enable --dry-run")
}

// T17: --timeout.
func TestParseArgs_Timeout(t *testing.T) {
	opts, err := parseArgs([]string{"--pid", "1", "--so", existingFile(t), "--timeout", "250ms"})
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, 250*time.Millisecond, opts.timeout)
}

func TestParseArgs_TimeoutInvalid(t *testing.T) {
	for _, args := range [][]string{
		{"--timeout", "abc"},
		{"--timeout", "0s"},
		{"--timeout", "-5s"},
		{"--timeout"},
	} {
		base := append([]string{"--pid", "1", "--so", existingFile(t)}, args...)
		_, err := parseArgs(base)
		assert.Error(t, err, "args %v must be rejected", args)
	}
}

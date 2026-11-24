package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseArgs_NoArgs(t *testing.T) {
	_, _, err := parseArgs(nil)
	assert.Error(t, err)
}

func TestParseArgs_PIDFlagOnly(t *testing.T) {
	_, _, err := parseArgs([]string{"--pid", "1234"})
	assert.Error(t, err) // missing --so
}

func TestParseArgs_SoFlagOnly(t *testing.T) {
	_, _, err := parseArgs([]string{"--so", "/tmp/test.so"})
	assert.Error(t, err) // missing --pid
}

func TestParseArgs_BothFlags(t *testing.T) {
	pid, libPath, err := parseArgs([]string{"--pid", "5678", "--so", "/tmp/lib.so"})
	assert.Error(t, err) // file not found
	assert.Equal(t, 5678, pid)
	assert.Equal(t, "/tmp/lib.so", libPath)
}

func TestParseArgs_InvalidPID(t *testing.T) {
	_, _, err := parseArgs([]string{"--pid", "abc", "--so", "/tmp/lib.so"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pid")
}

func TestParseArgs_SoNotExists(t *testing.T) {
	_, _, err := parseArgs([]string{"--pid", "1234", "--so", "/nonexistent/lib.so"})
	assert.Error(t, err)
}

func TestParseArgs_PIDZero(t *testing.T) {
	_, _, err := parseArgs([]string{"--pid", "0", "--so", "/tmp/lib.so"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pid")
}

func TestParseArgs_NegativePID(t *testing.T) {
	_, _, err := parseArgs([]string{"--pid", "-1", "--so", "/tmp/lib.so"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "pid")
}

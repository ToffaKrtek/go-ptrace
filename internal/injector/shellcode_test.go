//go:build linux && amd64

package injector

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Expected layout of the dlopen shellcode (x86_64, SysV ABI):
//
//	 0: 55                 push   rbp
//	 1: 48 89 e5           mov    rbp, rsp
//	 4: 48 83 e4 f0        and    rsp, -16          ; 16-byte stack alignment (T6)
//	 8: 48 b8 <8 bytes>    movabs rax, dlopenAddr
//	10..17                 dlopen address (LE)
//	18: be <4 bytes>       mov    esi, flags        ; 32-bit imm, zero-extends to RSI (T3,T4)
//	19..22                 flags (LE)
//	23: ff d0              call   rax
//	25: 48 89 ec           mov    rsp, rbp
//	28: 5d                 pop    rbp
//	29: cc                 int3                     ; trap for the tracer
const (
	scLen        = 30
	scAddrOffset = 10 // movabs rax imm64 data
	scEsiOffset  = 18 // "be" opcode of mov esi, imm32
	scCallOffset = 23 // "ff d0" call rax
)

// Helper for testing embedded address.
func binaryLittleEndianUint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// disassemble runs objdump over raw bytes (skipping the test if objdump is absent).
// This is the strongest proof that the instruction stream is well-formed: a wrong
// encoding (e.g. 0x66 0xbe imm8) silently swallows the following bytes.
func disassemble(t *testing.T, code []byte) string {
	t.Helper()
	path, err := exec.LookPath("objdump")
	if err != nil {
		t.Skip("objdump not available")
	}
	f := t.TempDir() + "/sc.bin"
	if err := os.WriteFile(f, code, 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	out, err := exec.Command(path, "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel", f).CombinedOutput()
	if err != nil {
		t.Fatalf("objdump: %v\n%s", err, out)
	}
	return string(out)
}

func TestShellcode_GeneratesNonEmpty(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 2) // RTLD_NOW
	assert.NoError(t, err)
	assert.NotEmpty(t, result, "shellcode must not be empty")
}

// T38: real length is 30 bytes, not the "39" claimed by the old doc comment.
func TestShellcode_CorrectLength(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 2)
	assert.NoError(t, err)
	assert.Equal(t, scLen, len(result), "shellcode length must be %d bytes", scLen)
}

func TestShellcode_EndsWithInt3(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 2)
	assert.NoError(t, err)
	assert.Equal(t, byte(0xcc), result[len(result)-1], "last byte must be int3 (0xcc)")
	// No trailing ret: the tracer restores RIP after int3, a ret is unreachable.
	for _, b := range result {
		assert.NotEqual(t, byte(0xc3), b, "shellcode must not contain a stray ret (0xc3)")
	}
}

func TestShellcode_EmbedsDlopenAddr(t *testing.T) {
	addr := uintptr(0xdeadbeef12345678)
	result, err := GenerateDlopenShellcode(addr, 2)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x48, 0xb8}, result[8:10], "movabs rax prefix at offset 8")
	assert.Equal(t, uint64(addr), binaryLittleEndianUint64(result[scAddrOffset:scAddrOffset+8]),
		"shellcode must embed dlopen address at offset %d", scAddrOffset)
}

// T3: call rax (0xff 0xd0) must be a standalone instruction, not swallowed as an
// immediate operand of a malformed mov.
func TestShellcode_CallRaxAtFixedOffset(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 2)
	assert.NoError(t, err)
	assert.Equal(t, []byte{0xff, 0xd0}, result[scCallOffset:scCallOffset+2],
		"call rax must sit at offset %d", scCallOffset)
}

// T4: mov esi, imm32 (opcode 0xBE + 4-byte LE immediate) zero-extends into RSI.
// The old 0x66 0xBE imm8 form only wrote SI and left garbage in the upper bits.
func TestShellcode_MovEsiImm32ZeroExtends(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags uint
		want  []byte
	}{
		{"RTLD_NOW", 2, []byte{0x02, 0x00, 0x00, 0x00}},
		{"RTLD_LAZY", 1, []byte{0x01, 0x00, 0x00, 0x00}},
		{"zero", 0, []byte{0x00, 0x00, 0x00, 0x00}},
		{"large", 0x104, []byte{0x04, 0x01, 0x00, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := GenerateDlopenShellcode(0x7f0000001000, tc.flags)
			assert.NoError(t, err)
			assert.Equal(t, byte(0xbe), result[scEsiOffset], "mov esi opcode must be 0xBE (no 0x66 prefix)")
			assert.NotEqual(t, byte(0x66), result[scEsiOffset-1], "must not use 16-bit 0x66 prefix")
			assert.Equal(t, tc.want, result[scEsiOffset+1:scEsiOffset+5],
				"flags must be a 4-byte little-endian immediate (upper bytes zero)")
		})
	}
}

// T6: and rsp, -16 must be present so rsp%16==0 at the moment of the call.
func TestShellcode_AlignsStack(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 2)
	assert.NoError(t, err)
	andRsp := []byte{0x48, 0x83, 0xe4, 0xf0}
	assert.Equal(t, andRsp, result[4:8], "shellcode must align stack with 'and rsp,-16' at offset 4")
	// Alignment must precede the call.
	assert.Less(t, bytes.Index(result, andRsp), scCallOffset, "stack alignment must come before call rax")
}

// The definitive check: objdump must decode a clean instruction stream that matches
// the intended semantics. A malformed encoding (old 0x66 0xBE imm8) would make objdump
// report "mov si" and destroy the "call rax".
func TestShellcode_DisassemblesAsExpected(t *testing.T) {
	addr := uintptr(0x7f00000012345678)
	result, err := GenerateDlopenShellcode(addr, 2)
	assert.NoError(t, err)
	dis := disassemble(t, result)

	assert.Contains(t, dis, "and    rsp,0xfffffffffffffff0", "objdump must show 'and rsp,-16' (T6)")
	assert.Contains(t, dis, "mov    esi,0x2", "objdump must show 'mov esi,0x2' (T3,T4)")
	assert.NotContains(t, dis, "mov    si,", "objdump must NOT show 16-bit 'mov si' (T4 regression)")
	assert.Contains(t, dis, "call   rax", "objdump must show a standalone 'call rax' (T3)")
	assert.Contains(t, dis, "int3", "objdump must end with int3")
	assert.Contains(t, dis, "movabs rax,0x7f00000012345678", "objdump must decode the dlopen address")
}

func TestShellcode_NullDlopenAddr(t *testing.T) {
	_, err := GenerateDlopenShellcode(0, 2)
	assert.Error(t, err, "dlopenAddr == 0 must return error")
	assert.Contains(t, strings.ToLower(err.Error()), "zero")
}

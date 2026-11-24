package injector

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShellcode_GeneratesNonEmpty(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 2) // RTLD_NOW
	assert.NoError(t, err)
	assert.NotEmpty(t, result, "shellcode must not be empty")
	assert.Greater(t, len(result), 0)
}

func TestShellcode_CorrectLength(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 2)
	assert.NoError(t, err)
	// Total: 31 bytes
	assert.Equal(t, 31, len(result), "shellcode length must be 31 bytes")
}

func TestShellcode_EndsWithInt3ThenRet(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 2)
	assert.NoError(t, err)
	// Shellcode ends with: int3 (0xcc) then ret (0xc3)
	// int3 stops the process, ret is a fallback return
	assert.Equal(t, byte(0xcc), result[len(result)-2], "second-to-last byte must be int3 (0xcc)")
	assert.Equal(t, byte(0xc3), result[len(result)-1], "last byte must be ret (0xc3)")
}

func TestShellcode_ContainsCallRax(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 2)
	assert.NoError(t, err)
	// Verify call rax (FF D0) exists
	foundCall := false
	for i := 0; i < len(result)-1; i++ {
		if result[i] == 0xff && result[i+1] == 0xd0 {
			foundCall = true
			break
		}
	}
	assert.True(t, foundCall, "shellcode must contain call rax (0xff 0xd0)")
}

func TestShellcode_EmbedsDlopenAddr(t *testing.T) {
	addr := uintptr(0xdeadbeef12345678)
	result, err := GenerateDlopenShellcode(addr, 2)
	assert.NoError(t, err)
	// movabs rax, <addr> = 0x48 0xb8 <8 bytes>
	// Address starts at offset 9 (opcode at 7-8, data at 9-16)
	importedAddr := binaryLittleEndianUint64(result[9:17])
	assert.Equal(t, uint64(addr), importedAddr, "shellcode must embed dlopen address")
}

func TestShellcode_ContainsMovEsi(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 2)
	assert.NoError(t, err)
	// mov esi, imm8 is encoded as 0x66 0xbe <imm8>
	found := false
	for i := 0; i < len(result)-2; i++ {
		if result[i] == 0x66 && result[i+1] == 0xbe {
			found = true
			break
		}
	}
	assert.True(t, found, "shellcode must contain mov esi, <flags>")
}

func TestShellcode_NullDlopenAddr(t *testing.T) {
	_, err := GenerateDlopenShellcode(0, 2)
	assert.Error(t, err, "dlopenAddr == 0 must return error")
	assert.Contains(t, err.Error(), "zero")
}

func TestShellcode_ZeroFlags(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 0)
	assert.NoError(t, err)
	assert.Equal(t, 31, len(result))
	// mov esi, imm8 = 0x66 0xbe <imm8> at offsets 17-19
	assert.Equal(t, byte(0x00), result[19], "flags byte must be 0")
}

func TestShellcode_RTLDGlobal(t *testing.T) {
	result, err := GenerateDlopenShellcode(0x7f0000001000, 1) // RTLD_GLOBAL
	assert.NoError(t, err)
	assert.Equal(t, byte(0x01), result[19], "flags byte must be 1 (RTLD_GLOBAL)")
}

// Helper for testing embedded address
func binaryLittleEndianUint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

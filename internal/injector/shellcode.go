//go:build linux && amd64

package injector

import (
	"encoding/binary"
	"fmt"
)

// dlopen shellcode for x86_64 (SysV ABI). The path address is passed in RDI by the
// tracer (set via PTRACE_SETREGS before hijacking RIP), and the flags are embedded as
// an immediate. After dlopen returns, RAX holds the handle and int3 traps back to the
// tracer, which restores the original registers — so the shellcode itself does not need
// to save/restore the target's registers.
//
//	push   rbp                      ; 55                    (1)
//	mov    rbp, rsp                 ; 48 89 e5              (3)
//	and    rsp, -16                 ; 48 83 e4 f0           (4)  ; 16-byte stack alignment (T6)
//	movabs rax, <dlopenAddr>        ; 48 b8 <8 bytes>       (10)
//	mov    esi, <flags>             ; be <4 bytes>          (5)  ; 32-bit imm zero-extends to RSI (T3,T4)
//	call   rax                      ; ff d0                 (2)
//	mov    rsp, rbp                 ; 48 89 ec              (3)
//	pop    rbp                      ; 5d                    (1)
//	int3                            ; cc                    (1)  ; trap for the tracer
//
// Total: 30 bytes. (The old doc comment claimed "31 bytes + 8 = 39", which was wrong;
// see audit note P.38.)
func GenerateDlopenShellcode(dlopenAddr uintptr, flags uint) ([]byte, error) {
	if dlopenAddr == 0 {
		return nil, fmt.Errorf("dlopen address must not be zero")
	}

	buf := make([]byte, 0, 30)

	// push rbp
	buf = append(buf, 0x55)
	// mov rbp, rsp
	buf = append(buf, 0x48, 0x89, 0xe5)
	// and rsp, -16  (align the stack before the call, as required by SysV ABI)
	buf = append(buf, 0x48, 0x83, 0xe4, 0xf0)
	// movabs rax, <dlopenAddr>
	buf = append(buf, 0x48, 0xb8)
	buf = append(buf, makeUint64Bytes(uint64(dlopenAddr))...)
	// mov esi, <flags>  (BE + imm32: zero-extends into the upper bits of RSI)
	buf = append(buf, 0xbe)
	buf = append(buf, makeUint32Bytes(uint32(flags))...)
	// call rax
	buf = append(buf, 0xff, 0xd0)
	// mov rsp, rbp
	buf = append(buf, 0x48, 0x89, 0xec)
	// pop rbp
	buf = append(buf, 0x5d)
	// int3 (trap back to the tracer)
	buf = append(buf, 0xcc)

	return buf, nil
}

func makeUint64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

func makeUint32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

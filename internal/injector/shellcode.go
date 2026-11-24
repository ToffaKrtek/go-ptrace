package injector

import (
	"encoding/binary"
	"fmt"
)

//	push rbp              ; 0x55                    1 byte
//	mov rbp, rsp          ; 0x48 0x89 0xe5          3 bytes
//	push rax              ; 0x50                    1 byte
//	push rsi              ; 0x56                    1 byte
//	push rbx              ; 0x53                    1 byte
//	movabs rax, <addr>    ; 0x48 0xb8 <8 bytes>     10 bytes
//	mov esi, <flags>      ; 0x66 0xbe <1 byte>      3 bytes
//	call rax              ; 0xff 0xd0               2 bytes
//	pop rbx               ; 0x5b                    1 byte
//	pop rsi               ; 0x5e                    1 byte
//	pop rax               ; 0x58                    1 byte
//	mov rsp, rbp          ; 0x48 0x89 0xec          3 bytes
//	pop rbp               ; 0x5d                    1 byte
//	int3                  ; 0xcc                    1 byte
//	ret                   ; 0xc3                    1 byte
// Total: 31 bytes + 8 bytes for dlopen address = 39 bytes

func GenerateDlopenShellcode(dlopenAddr uintptr, flags uint) ([]byte, error) {
	if dlopenAddr == 0 {
		return nil, fmt.Errorf("dlopen address must not be zero")
	}

	buf := make([]byte, 0, 39)

	// push rbp
	buf = append(buf, 0x55)
	// mov rbp, rsp
	buf = append(buf, 0x48, 0x89, 0xe5)
	// push rax
	buf = append(buf, 0x50)
	// push rsi
	buf = append(buf, 0x56)
	// push rbx
	buf = append(buf, 0x53)
	// movabs rax, <dlopenAddr>
	buf = append(buf, 0x48, 0xb8)
	buf = append(buf, makeUint64Bytes(uint64(dlopenAddr))...)
	// mov esi, <flags> (RTLD_NOW = 2)
	buf = append(buf, 0x66, 0xbe)
	buf = append(buf, byte(flags))
	// call rax
	buf = append(buf, 0xff, 0xd0)
	// pop rbx
	buf = append(buf, 0x5b)
	// pop rsi
	buf = append(buf, 0x5e)
	// pop rax
	buf = append(buf, 0x58)
	// mov rsp, rbp
	buf = append(buf, 0x48, 0x89, 0xec)
	// pop rbp
	buf = append(buf, 0x5d)
	// int3 (stop for debugger/tracer)
	buf = append(buf, 0xcc)
	// ret (return to caller)
	buf = append(buf, 0xc3)

	return buf, nil
}

func makeUint64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return b
}

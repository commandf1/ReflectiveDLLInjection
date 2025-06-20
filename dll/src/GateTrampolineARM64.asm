;
; ARM64 Syscall Trampoline for Reflective DLL Injection
; Microsoft ARM64 Assembler (armasm64.exe) syntax.
;
    AREA    |.text|, CODE, READONLY, ALIGN=3
    EXPORT  DoSyscall

DoSyscall
    ; Preserve callee-saved register x19 and the link register x30
    STP     x19, x30, [sp, #-16]!

    ; The C wrapper called us. x0 holds the pSyscall pointer.
    MOV     x19, x0

    ; Rearrange the C arguments (in x1-x7) into the syscall argument
    ; registers (x0-x6) as required by the Windows ARM64 syscall ABI.
    MOV     x0, x1
    MOV     x1, x2
    MOV     x2, x3
    MOV     x3, x4
    MOV     x4, x5
    MOV     x5, x6
    MOV     x6, x7

    ; The pStub now points directly to the ntdll!Zw* function, which
    ; contains the necessary 'svc #imm' instruction. We do NOT load
    ; the syscall number into x8; it's already encoded in the stub.
    LDR     x10, [x19, #16] ; Load pStub into x10

    ; Branch With Link to the ntdll function stub.
    BLR     x10

    ; The syscall's return value is now in x0, the correct C return register.

    ; Restore the saved registers
    LDP     x19, x30, [sp], #16

    ; Return to the C caller
    RET

    ALIGN
    END
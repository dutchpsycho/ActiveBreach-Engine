; ==================================================================================
;  File:         stub.asm
;  Author:       DutchPsycho
;  Description:
;      This is unused.
;      It moves the syscall number into eax, sets r10 to rcx, then executes syscall.
; ==================================================================================

.386
.model flat, stdcall
option casemap :none

.code

CreateStub PROC PUBLIC
    mov r10, rcx        ; r10 = first arg (arg1 -> target_address)
    mov eax, edx        ; eax = second arg (arg2 -> ssn)
    syscall             ; perform syscall
    ret                 ; return
CreateStub ENDP

END
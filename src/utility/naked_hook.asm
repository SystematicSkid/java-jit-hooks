; Pointer[0] = Whether support for XSAVE is available
; Pointer[1] = Size required for saved FPU state using XSAVE or FXSAVE
; Pointer[2] = Address of callback function
; Pointer[3] = Address of next hook
SHELL_PTR_ELEMS EQU 4
SHELL_ENDCODE_MAGIC EQU 02BAD4B0BBAADBABEh

; Macro for preserving all general purpose registers
save_cpu_state_gpr MACRO
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    pushfq
ENDM

; Macro for restoring all general purpose registers
restore_cpu_state_gpr MACRO
    popfq
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
    ; This should only be used if the return value is not needed
	; pop rax
ENDM

; Shared macro for initializing the FPU state for saving/restoring
setup_fpu_state MACRO fpu_state_args
    ; Make sure the labels are unique since they are used multiple times within a single procedure
    Local fpu_state_alignstack_xsave
    Local fpu_state_alignstack_end

    ; Mask used by XSAVE/FSXAVE
    push rdx
    push rax

    ; Preserve flags
    pushfq

    ; Aligned stack for XSAVE/FXSAVE
    ; This must be done last so that preserved registers are not overwritten
    push rcx
    lea rcx, [rsp + 08h]

    ; Allocate space on stack for FPU state
    sub rcx, qword ptr [fpu_state_args + 08h]

    ; Sets the mask used by XSAVE/FXSAVE them to 0xFFFFFFFFFFFFFFFF prior to the instruction in order to save the entire FPU state
    mov rdx, 0FFFFFFFFFFFFFFFFh
    mov rax, 0FFFFFFFFFFFFFFFFh

    ; Check for XSAVE support
    cmp qword ptr [fpu_state_args], 1
    je fpu_state_alignstack_xsave

    ; FXSAVE (16-Byte Aligned Stack)
    and rcx, 0FFFFFFFFFFFFFFF0h
    jmp fpu_state_alignstack_end

fpu_state_alignstack_xsave:
    ; XSAVE (64-Byte Aligned Stack)
    and rcx, 0FFFFFFFFFFFFFFC0h

fpu_state_alignstack_end:
ENDM

; Saves the full FPU state
save_fpu_state MACRO fpu_state_args
    setup_fpu_state fpu_state_args

    cmp qword ptr [fpu_state_args], 1
    je save_fpu_state_xsave

	fxsave [rcx]
    jmp save_fpu_state_end

save_fpu_state_xsave:
	xsave [rcx]

save_fpu_state_end:
	pop rcx
	popfq
    pop rax
    pop rdx
ENDM

; Restores the full FPU state
restore_fpu_state MACRO fpu_state_args
	setup_fpu_state fpu_state_args

	cmp qword ptr [fpu_state_args], 1
	je restore_fpu_state_xsave

	fxrstor [rcx]
	jmp restore_fpu_state_end

restore_fpu_state_xsave:
	xrstor [rcx]

restore_fpu_state_end:
	pop rcx
    popfq
    pop rax
    pop rdx
ENDM

.CODE

; This is a simple wrapper function to access the magic number marking the end of the shellcode stub.
jhook_end_shellcode_magic PROC
    mov rax, SHELL_ENDCODE_MAGIC
    ret
jhook_end_shellcode_magic ENDP

; This is a simple wrapper function to access the constant SHELL_PTR_ELEMS.
jhook_shellcode_numelems PROC
	mov eax, SHELL_PTR_ELEMS
	ret
jhook_shellcode_numelems ENDP

; This is a simple wrapper to get the base function address for the first instruction of the shellcode.
jhook_shellcode_getcode PROC
	mov rax, jhook_shellcode_stub
    lea rax, [rax + SHELL_PTR_ELEMS * 08h]
	ret
jhook_shellcode_getcode ENDP

; Naked function, so no prologue or epilogue generated by the compiler
; Do not remove the ALIGN directive
ALIGN 8
jhook_shellcode_stub PROC
    ; Dynamic array of values used by the shellcode.
	dyn_addr_arr QWORD SHELL_PTR_ELEMS DUP(0)

    ; Preserve the registers, flags, and FPU state
    save_cpu_state_gpr
    save_fpu_state dyn_addr_arr

    ; Prepare for the subroutine call
    mov rcx, rsp
    
    ; Allocate space on stack for all registers and flags
    sub rsp, 28h

    ; Call subroutine at callAddress
    mov r10, qword ptr [dyn_addr_arr + 10h] ; Replaced with the address of the callback
    call r10
    
    ; Deallocate the space on the stack
    add rsp, 28h

    ; Restore the registers, flags, and FPU state
    restore_cpu_state_gpr
    add rsp, 8h ; Simulate pop so the FPU state is restored properly since 'restore_fpu_state' does not pop RAX
    restore_fpu_state dyn_addr_arr
    sub rsp, 8h ; Restore the stack pointer to its original position now that the FPU state is restored

    ; Check if r10 = 1
    cmp r10, 1
    ; Branch to next_hook if r10 = 1
    je next_hook
    ; Restore rax if we are not branching
    pop rax
    ; Jump to the original function (or the next hook)
    mov r10, qword ptr [dyn_addr_arr + 18h] ; Replaced with the address of the next hook
    jmp r10
    ; Label to ret instead of jmp
next_hook:
    ; Simulate pop
    add rsp, 8
    ret

end_shellcode:
    qword SHELL_ENDCODE_MAGIC

jhook_shellcode_stub ENDP

END
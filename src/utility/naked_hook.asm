.CODE
; Naked function, so no prologue or epilogue generated by the compiler
; Note: Does not preserve XMM registers
naked_shell PROC
    ; Push all registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi 
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    pushfq  ; Push the flags register

    ; Prepare for the subroutine call
    mov rcx, rsp
    
    ; Allocate space on stack for all registers and flags
    sub rsp, 28h

    ; Call subroutine at callAddress
    mov r10, 100000000h ; Replaced with the address of the callback
    call r10
    
    ; Deallocate the space on the stack
    add rsp, 28h

    ; Restore the registers and flags
    popfq
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ; Check if r10 = 1
    cmp r10, 1
    ; Branch to next_hook if r10 = 1
    je next_hook
    ; Restore rax if we are not branching
    pop rax
    ; Jump to the original function (or the next hook)
    mov r10, 100000000h ; Replaced with the address of the next hook
    jmp r10
    ; Label to ret instead of jmp
next_hook:
    ; Simulate pop
    add rsp, 8
    ret

naked_shell ENDP

END
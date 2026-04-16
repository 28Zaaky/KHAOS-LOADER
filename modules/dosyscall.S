# By Z4vky 
# DoSyscall - Indirect syscall stub (6 args)
# Caller: RCX=SSN, RDX=syscallAddr, R8=arg1, R9=arg2, stack=arg3..6
# Syscall: EAX=SSN, R10=arg1, RDX=arg2, R8=arg3, R9=arg4, stack=arg5..6

.text
.globl DoSyscall
.def DoSyscall; .scl 2; .type 32; .endef

DoSyscall:
    pushq %rbx
    pushq %rsi

    movq %rdx, %rbx             # save syscall gadget address
    movl %ecx, %esi             # save SSN

    # remap args to syscall ABI
    movq %r8, %r10              # arg1
    movq %r9, %rdx              # arg2
    movq 0x38(%rsp), %r8        # arg3 (offset accounts for 2 pushes)
    movq 0x40(%rsp), %r9        # arg4

    subq $0x38, %rsp            # shadow space (32) + stack args (24)

    movq 0x80(%rsp), %rax       # arg5
    movq %rax, 0x20(%rsp)
    movq 0x88(%rsp), %rax       # arg6
    movq %rax, 0x28(%rsp)

    movl %esi, %eax             # EAX = SSN
    call *%rbx                  # indirect call through gadget

    addq $0x38, %rsp
    popq %rsi
    popq %rbx
    ret

# DoSyscall11 - Indirect syscall stub (11 args)
# Caller: RCX=SSN, RDX=syscallAddr, R8=arg1, R9=arg2, stack=arg3..11
# Syscall: EAX=SSN, R10=arg1, RDX=arg2, R8=arg3, R9=arg4, stack=arg5..11

.globl DoSyscall11
.def DoSyscall11; .scl 2; .type 32; .endef

DoSyscall11:
    pushq %rbx
    pushq %rsi
    pushq %rdi
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    # 7 pushes = 0x38 bytes; arg3 originally at [RSP+0x28] → now [RSP+0x60]

    movq %rdx, %rbx             # save syscall gadget address
    movl %ecx, %esi             # save SSN

    movq %r8, %r10              # arg1
    movq %r9, %rdx              # arg2
    movq 0x60(%rsp), %r8        # arg3
    movq 0x68(%rsp), %r9        # arg4

    subq $0x58, %rsp            # shadow (32) + 7 stack args (56)

    movq 0xC8(%rsp), %rax; movq %rax, 0x20(%rsp)   # arg5
    movq 0xD0(%rsp), %rax; movq %rax, 0x28(%rsp)   # arg6
    movq 0xD8(%rsp), %rax; movq %rax, 0x30(%rsp)   # arg7
    movq 0xE0(%rsp), %rax; movq %rax, 0x38(%rsp)   # arg8
    movq 0xE8(%rsp), %rax; movq %rax, 0x40(%rsp)   # arg9
    movq 0xF0(%rsp), %rax; movq %rax, 0x48(%rsp)   # arg10
    movq 0xF8(%rsp), %rax; movq %rax, 0x50(%rsp)   # arg11

    movl %esi, %eax             # EAX = SSN
    call *%rbx                  # indirect call through gadget

    addq $0x58, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rdi
    popq %rsi
    popq %rbx
    ret

#===============================================================================
# DoSyscall - Indirect Syscall Stub
#===============================================================================
# Windows x64 appel:
#   RCX=ssn, RDX=syscallAddr, R8=arg1, R9=arg2, [RSP+0x28..0x40]=arg3..arg6
# Syscall attend:
#   EAX=SSN, R10=arg1, RDX=arg2, R8=arg3, R9=arg4, [RSP+0x28..0x30]=arg5,arg6
#===============================================================================

.text
.globl DoSyscall
.def DoSyscall; .scl 2; .type 32; .endef

DoSyscall:
    # Sauvegarder les registres non-volatiles qu'on va utiliser
    pushq %rbx
    pushq %rsi
    
    # Sauvegarder syscallAddr et SSN
    movq %rdx, %rbx             # RBX = syscallAddr
    movl %ecx, %esi             # ESI = SSN (32-bit suffit)
    
    # Charger tous les arguments AVANT de modifier la pile
    # R10 = arg1, RDX = arg2, R8 = arg3, R9 = arg4
    movq %r8, %r10              # R10 = arg1 (déjà bon registre)
    movq %r9, %rdx              # RDX = arg2
    movq 0x38(%rsp), %r8        # R8  = arg3 (0x28 + 0x10 pour les 2 push)
    movq 0x40(%rsp), %r9        # R9  = arg4
    
    # Maintenant configurer la pile pour le CALL
    # On doit mettre arg5 et arg6 aux bonnes positions
    # Actuellement: arg5 à [RSP+0x48], arg6 à [RSP+0x50] (à cause des 2 push)
    # Après sub et call: arg5 doit être à [RSP+0x28], arg6 à [RSP+0x30]
    
    subq $0x38, %rsp            # Allouer 56 bytes (shadow 32 + 24 pour args)
    
    # Copier arg5 et arg6
    movq 0x80(%rsp), %rax       # arg5 original (0x48+0x38=0x80)
    movq %rax, 0x20(%rsp)       # arg5 à RSP+0x20 → RSP+0x28 après CALL
    
    movq 0x88(%rsp), %rax       # arg6 original (0x50+0x38=0x88)
    movq %rax, 0x28(%rsp)       # arg6 à RSP+0x28 → RSP+0x30 après CALL
    
    # Configurer SSN
    movl %esi, %eax
    
    # CALL syscall
    call *%rbx
    
    # Nettoyer
    addq $0x38, %rsp
    popq %rsi
    popq %rbx
    ret

#===============================================================================
# DoSyscall11 - Extended version for 11 arguments
#===============================================================================
# Windows x64 call: RCX=ssn, RDX=syscallAddr, R8..R9=arg1..2, stack=arg3..11
# Syscall expects: EAX=SSN, R10=arg1, RDX=arg2, R8=arg3, R9=arg4, stack=arg5..11
#===============================================================================

.globl DoSyscall11
.def DoSyscall11; .scl 2; .type 32; .endef

DoSyscall11:
    # Sauvegarder registres non-volatiles
    pushq %rbx
    pushq %rsi
    pushq %rdi
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    
    # Total pushes: 7*8 = 56 bytes (0x38)
    # RSP initial: 0x00
    # Après pushes: 0x38
    # arg3 à [RSP+0x28] → [RSP+0x60]
    
    movq %rdx, %rbx             # RBX = syscallAddr
    movl %ecx, %esi             # ESI = SSN
    
    # Charger arg1..4 dans les registres
    movq %r8, %r10              # R10 = arg1
    movq %r9, %rdx              # RDX = arg2
    movq 0x60(%rsp), %r8        # R8 = arg3 (0x28 + 0x38 pushes)
    movq 0x68(%rsp), %r9        # R9 = arg4
    
    # Allouer espace pour shadow + 7 args sur pile (arg5..arg11)
    # shadow=32, args=7*8=56 → total=88 (0x58)
    subq $0x58, %rsp
    
    # Copier arg5..arg11 depuis pile caller vers pile syscall
    # Avant sub: arg5 à [RSP+0x70], après sub: à [RSP+0xC8]
    # Après CALL: [RSP+0x20] → [RSP+0x28]
    
    movq 0xC8(%rsp), %rax       # arg5 (0x70 + 0x58)
    movq %rax, 0x20(%rsp)       # → RSP+0x28 après CALL
    
    movq 0xD0(%rsp), %rax       # arg6
    movq %rax, 0x28(%rsp)
    
    movq 0xD8(%rsp), %rax       # arg7
    movq %rax, 0x30(%rsp)
    
    movq 0xE0(%rsp), %rax       # arg8
    movq %rax, 0x38(%rsp)
    
    movq 0xE8(%rsp), %rax       # arg9
    movq %rax, 0x40(%rsp)
    
    movq 0xF0(%rsp), %rax       # arg10
    movq %rax, 0x48(%rsp)
    
    movq 0xF8(%rsp), %rax       # arg11
    movq %rax, 0x50(%rsp)
    
    # Configurer SSN et CALL
    movl %esi, %eax
    call *%rbx
    
    # Nettoyer
    addq $0x58, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rdi
    popq %rsi
    popq %rbx
    ret

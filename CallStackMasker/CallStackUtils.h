#pragma once
#include <ehdata.h>
#include <iostream>
#include <intrin.h>
#include <map>
#include <vector>
#include <Windows.h>
#include "psapi.h"
#pragma comment(lib,"ntdll.lib")

//
// From Ntdef.h.
//
// Treat anything not STATUS_SUCCESS as an error.
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL  ((NTSTATUS) 0x00000001L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS) 0xC0000004L)

#define ThreadQuerySetWin32StartAddress 9
#define SystemProcessInformation 5
#define RBP_OP_INFO 0x5

// Dynamic spoof options.
// NB This PoC only supports WaitForSingleObjectEx.
std::string targetWaitModule("kernelbase");
std::string targetWaitFunction("WaitForSingleObjectEx");

// Struct to store info on target thread to copy.
typedef struct
{
    DWORD dwPid;
    DWORD dwTid;
    PVOID startAddr;
    ULONG totalRequiredStackSize;
    PVOID pFakeStackBuffer;
} threadToSpoof;

/*
    Structs to call NtQuerySystemInformation.
    Based on: https://github.com/thefLink/Hunt-Sleeping-Beacons/blob/main/source/Nt.h
*/
typedef NTSTATUS(WINAPI* pNtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(int, PVOID, ULONG, PULONG);

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct
{
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS;

typedef struct
{
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority;
    LONG BasePriority;
    ULONG ContextSwitches;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION;

typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    FILETIME CreateTime;
    FILETIME UserTime;
    FILETIME KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
#ifdef _WIN64
    ULONG pad1;
#endif
    ULONG ProcessId;
#ifdef _WIN64
    ULONG pad2;
#endif
    ULONG InheritedFromProcessId;
#ifdef _WIN64
    ULONG pad3;
#endif
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    VM_COUNTERS VirtualMemoryCounters;
    ULONG_PTR PrivatePageCount;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD_INFORMATION ThreadInfos[1];
} SYSTEM_PROCESS_INFORMATION;

/*
   Thread WaitReason enum, based on https://gist.github.com/TheWover/799822ce3d1239e0bd5764ac0b0adfda.
*/
typedef enum _KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    MaximumWaitReason
} KWAIT_REASON, * PKWAIT_REASON;

/*
    The utility functions/structs below are based on the following two PoCs:
    - https://github.com/WithSecureLabs/CallStackSpoofer
    - https://github.com/WithSecureLabs/TickTock
    Full credit to @WithSecureLabs.
*/

//
// A lookup map for modules and their corresponding image base.
//
typedef std::map<std::string, HMODULE> imageMap;
// std::wstring equivalent.
std::map<std::wstring, HMODULE> imageBaseMap;

//
// Used to store information for individual stack frames for call stack to spoof.
//
struct StackFrame {
    std::wstring targetDll;
    std::string targetFunc;
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;
    StackFrame() = default;
    StackFrame(std::wstring dllPath, std::string function, ULONG targetOffset, ULONG targetStackSize, bool bDllLoad) :
        targetDll(dllPath),
        targetFunc(function),
        offset(targetOffset),
        totalStackSize(targetStackSize),
        requiresLoadLibrary(bDllLoad),
        setsFramePointer(false),
        returnAddress(0),
        pushRbp(false),
        countOfCodes(0),
        pushRbpIndex(0)
    {
    };
};

//
// Unwind op codes: https://docs.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170.
//
typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

//
// Calculates the image base for the given stack frame
// and adds it to the image base map.
//
NTSTATUS GetImageBase(const StackFrame& stackFrame)
{
    NTSTATUS status = STATUS_SUCCESS;
    HMODULE tmpImageBase = 0;

    // [0] Check if image base has already been resolved.
    if (imageBaseMap.count(stackFrame.targetDll))
    {
        goto Cleanup;
    }

    // [1] Check if current frame contains a
    // non standard dll and load if so.
    if (stackFrame.requiresLoadLibrary)
    {
        tmpImageBase = LoadLibrary(stackFrame.targetDll.c_str());
        if (!tmpImageBase)
        {
            status = STATUS_DLL_NOT_FOUND;
            goto Cleanup;
        }
    }

    // [2] If we haven't already recorded the
    // image base capture it now.
    if (!tmpImageBase)
    {
        tmpImageBase = GetModuleHandle(stackFrame.targetDll.c_str());
        if (!tmpImageBase)
        {
            status = STATUS_DLL_NOT_FOUND;
            goto Cleanup;
        }
    }

    // [3] Add to image base map to avoid superfluous recalculating.
    imageBaseMap.insert({ stackFrame.targetDll, tmpImageBase });

Cleanup:
    return status;
}

//
// Uses the offset within the StackFrame structure to
// calculate the return address for fake frame.
// *Modified this to use GetProcAddress + offset in function*.
//
NTSTATUS CalculateReturnAddress(StackFrame& stackFrame)
{
    NTSTATUS status = STATUS_SUCCESS;

    try {
        const PVOID targetImageBaseAddress = imageBaseMap.at(stackFrame.targetDll);
        if (!targetImageBaseAddress) {
            status = STATUS_DLL_NOT_FOUND;
            goto Cleanup;
        }
        auto funcAddr = GetProcAddress((HMODULE)targetImageBaseAddress, stackFrame.targetFunc.c_str());
        if (!funcAddr) {
            status = STATUS_ORDINAL_NOT_FOUND;
            goto Cleanup;
        }
        stackFrame.returnAddress = (PCHAR)funcAddr + stackFrame.offset;
    }
    catch (const std::out_of_range&)
    {
        std::cout << "Dll \"" << stackFrame.targetDll.c_str() << "\" not found" << std::endl;
        status = STATUS_DLL_NOT_FOUND;
        goto Cleanup;
    }

Cleanup:
    return status;
}

//
// Calculates the total stack space used by the fake stack frame. Uses
// a minimal implementation of RtlVirtualUnwind to parse the unwind codes
// for target function and add up total stack size. Largely based on:
// https://github.com/hzqst/unicorn_pe/blob/master/unicorn_pe/except.cpp#L773
//
NTSTATUS CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunction, const DWORD64 ImageBase, StackFrame& stackFrame)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUNWIND_INFO pUnwindInfo = NULL;
    ULONG unwindOperation = 0;
    ULONG operationInfo = 0;
    ULONG index = 0;
    ULONG frameOffset = 0;

    // [0] Sanity check incoming pointer.
    if (!pRuntimeFunction)
    {
        std::cout << "    [-] No RUNTIME_FUNCTION found for target function.\n";
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Loop over unwind info.
    // NB As this is a PoC, it does not handle every unwind operation, but
    // rather the minimum set required to successfully mimic the default
    // call stacks included.
    pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunction->UnwindData + ImageBase);
    while (index < pUnwindInfo->CountOfCodes)
    {
        unwindOperation = pUnwindInfo->UnwindCode[index].UnwindOp;
        operationInfo = pUnwindInfo->UnwindCode[index].OpInfo;
        // [2] Loop over unwind codes and calculate
        // total stack space used by target function.
        switch (unwindOperation) {
        case UWOP_PUSH_NONVOL:
            // UWOP_PUSH_NONVOL is 8 bytes.
            stackFrame.totalStackSize += 8;
            // Record if it pushes rbp as
            // this is important for UWOP_SET_FPREG.
            if (RBP_OP_INFO == operationInfo)
            {
                stackFrame.pushRbp = true;
                // Record when rbp is pushed to stack.
                stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
                stackFrame.pushRbpIndex = index + 1;
            }
            break;
        case UWOP_SAVE_NONVOL:
            //UWOP_SAVE_NONVOL doesn't contribute to stack size
            // but you do need to increment index.
            index += 1;
            break;
        case UWOP_ALLOC_SMALL:
            //Alloc size is op info field * 8 + 8.
            stackFrame.totalStackSize += ((operationInfo * 8) + 8);
            break;
        case UWOP_ALLOC_LARGE:
            // Alloc large is either:
            // 1) If op info == 0 then size of alloc / 8
            // is in the next slot (i.e. index += 1).
            // 2) If op info == 1 then size is in next
            // two slots.
            index += 1;
            frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
            if (operationInfo == 0)
            {
                frameOffset *= 8;
            }
            else
            {
                index += 1;
                frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
            }
            stackFrame.totalStackSize += frameOffset;
            break;
        case UWOP_SET_FPREG:
            // This sets rsp == rbp (mov rsp,rbp), so we need to ensure
            // that rbp is the expected value (in the frame above) when
            // it comes to spoof this frame in order to ensure the
            // call stack is correctly unwound.
            stackFrame.setsFramePointer = true;
            break;
        default:
            std::cout << "    [-] Error: Unsupported Unwind Op Code\n";
            status = STATUS_ASSERTION_FAILURE;
            goto Cleanup;
        }

        index += 1;
    }

    // If chained unwind information is present then we need to
    // also recursively parse this and add to total stack size.
    if (0 != (pUnwindInfo->Flags & UNW_FLAG_CHAININFO))
    {
        index = pUnwindInfo->CountOfCodes;
        if (0 != (index & 1))
        {
            index += 1;
        }
        pRuntimeFunction = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
        return CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);
    }

    // Add the size of the return address (8 bytes).
    stackFrame.totalStackSize += 8;

Cleanup:
    return status;
}

//
// Retrieves the runtime function entry for given fake ret address
// and calls CalculateFunctionStackSize, which will recursively
// calculate the total stack space utilisation.
//
NTSTATUS CalculateFunctionStackSizeWrapper(StackFrame& stackFrame)
{
    NTSTATUS status = STATUS_SUCCESS;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    DWORD64 ImageBase = 0;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;

    // [0] Sanity check return address.
    if (!stackFrame.returnAddress)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Locate RUNTIME_FUNCTION for given function.
    pRuntimeFunction = RtlLookupFunctionEntry(
        (DWORD64)stackFrame.returnAddress,
        &ImageBase,
        pHistoryTable);
    if (NULL == pRuntimeFunction)
    {
        status = STATUS_ASSERTION_FAILURE;
        goto Cleanup;
    }

    // [2] Recursively calculate the total stack size for
    // the function we are "returning" to.
    status = CalculateFunctionStackSize(pRuntimeFunction, ImageBase, stackFrame);

Cleanup:
    return status;
}

//
// Takes a target call stack and configures it ready for use
// via loading any required dlls, resolving module addresses,
// and calculating spoofed return addresses.
//
NTSTATUS InitialiseSpoofedCallstack(std::vector<StackFrame>& targetCallStack)
{
    NTSTATUS status = STATUS_SUCCESS;

    for (auto stackFrame = targetCallStack.begin(); stackFrame != targetCallStack.end(); stackFrame++)
    {
        // [1] Get image base for current stack frame.
        status = GetImageBase(*stackFrame);
        if (!NT_SUCCESS(status))
        {
            std::cout << "[-] Error: Failed to get image base\n";
            goto Cleanup;
        }

        // [2] Calculate ret address for current stack frame.
        status = CalculateReturnAddress(*stackFrame);
        if (!NT_SUCCESS(status))
        {
            std::cout << "[-] Error: Failed to calculate ret address\n";
            goto Cleanup;
        }

        // [3] Calculate the total stack size for ret function.
        status = CalculateFunctionStackSizeWrapper(*stackFrame);
        if (!NT_SUCCESS(status))
        {
            std::cout << "[-] Error: Failed to caluclate total stack size\n";
            goto Cleanup;
        }
    }

Cleanup:
    return status;
}

//
// Templated wrappers around ReadProcessMemory.
//
template<typename T>
T readProcessMemory(HANDLE hProcess, LPVOID targetAddress)
{
    T returnValue;
    (void)ReadProcessMemory(hProcess, targetAddress, &returnValue, sizeof(T), NULL);
    return returnValue;
};

//
// Takes an address and retrieves the base name of the specified module.
//
NTSTATUS GetModuleBaseNameWrapper(HANDLE hProcess, PVOID targetAddress, std::string& moduleName)
{
    NTSTATUS status = STATUS_SUCCESS;
    char szModuleBaseName[MAX_PATH];

    if (GetModuleBaseNameA(hProcess, (HMODULE)targetAddress, szModuleBaseName, sizeof(szModuleBaseName)))
    {
        moduleName = szModuleBaseName;
    }
    else
    {
        printf("    [-] GetModuleBaseName returned error : %d\n", GetLastError());
        status = STATUS_ASSERTION_FAILURE;
    }

    return status;
}

/*
   CallStackMasker utility functions.
*/

NTSTATUS HandleArgs(int argc, char* argv[], BOOL& bStaticCallStack)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (argc < 2)
    {
        goto Cleanup;
    }
    else
    {
        std::string callstackArg(argv[1]);
        if (callstackArg == "--dynamic")
        {
            bStaticCallStack = false;
        }
        else
        {
            std::cout << "[-] Error: Incorrect argument provided. The options are: --dynamic\n";
            status = ERROR_INVALID_PARAMETER;
        }
    }

Cleanup:
    return status;
}

//
// Retrieve Child-SP for caller.
//
__declspec(noinline) void* GetChildSP()
{
    // Add 8 to get correct Child-SP for frame.
    return (PCHAR)_AddressOfReturnAddress() + 8;
}

/*
    Static call stack masking functions.
*/

//
// Calculates total stack space for a given static call stack.
//
ULONG CalculateStaticStackSize(const std::vector<StackFrame>& targetCallStack)
{
    ULONG totalStackCount = 0x0;
    for (auto entry : targetCallStack)
    {
        totalStackCount += entry.totalStackSize;
    }
    // Add 0x8 so we can write 0x0 as last
    // address and stop stack unwinding.
    totalStackCount += 0x8;
    return totalStackCount;
}

//
// Creates a buffer containing a fake call stack layout.
//
NTSTATUS CreateFakeStackInBuffer(const std::vector<StackFrame>& targetCallStack, const PVOID pSpoofedStack)
{
    NTSTATUS status = STATUS_SUCCESS;
    int64_t* index = NULL;

    // [0] Sanity check incoming ptr.
    if (NULL == pSpoofedStack)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    // [1] Loop over buffer and create desired stack layout.
    // NB This should be sanity checked for overflows but ignored for PoC.
    index = (int64_t*)pSpoofedStack;
    for (auto entry : targetCallStack)
    {
        // Write ret address.
        *index = (int64_t)entry.returnAddress;
        // Increment index to next Child-SP + 0x8;
        auto offset = entry.totalStackSize / sizeof(int64_t);
        index += offset;
    }

    // [2] Stop stack unwinding by writing 0x0 at end of buffer.
    *index = 0x0;

Cleanup:
    return status;
}

//
// Creates a fake stack layout in memory based on a given *static* call stack.
//
NTSTATUS InitialiseStaticCallStackSpoofing(std::vector<StackFrame>& targetCallStack, threadToSpoof& thread)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE hHeap = NULL;

    // [1] Initialise the target call stack.
    if (!NT_SUCCESS(InitialiseSpoofedCallstack(targetCallStack)))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // [2] Calculate total stack space required for fake call stack.
    thread.totalRequiredStackSize = CalculateStaticStackSize(targetCallStack);

    // [3] Allocate heap memory for required stack size.
    // NB this is currently never freed but it is irrelevant as PoC runs on while true loop.
    hHeap = GetProcessHeap();
    if (!hHeap)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }
    thread.pFakeStackBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, thread.totalRequiredStackSize);
    if (!thread.pFakeStackBuffer)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    // [4] Create fake stack.
    if (!NT_SUCCESS(CreateFakeStackInBuffer(targetCallStack, thread.pFakeStackBuffer)))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }
    //std::cout << "[+] Fake stack is at: 0x" << std::hex << thread.pFakeStackBuffer << "\n";

Cleanup:
    return status;
}

/*
    Dynamic call stack masking functions.
*/

//
// Retrieve a thread's starting address.
//
NTSTATUS GetThreadStartAddress(const HANDLE hThread, PVOID& startAddress)
{
    NTSTATUS status = STATUS_SUCCESS;

    pNtQueryInformationThread NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
    if (!NtQueryInformationThread)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

    if (!NT_SUCCESS(NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), NULL)))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }

Cleanup:
    return status;
}

//
// Checks if a ret address found on a stack is located within a specified function.
//
BOOL CheckIfAddressIsWithinTargetFunc(const PVOID targetAddress, const std::string targetModule, const std::string targetFunction)
{
    BOOL bAddressIsWithinTargetFunc = FALSE;

    HMODULE hModule = NULL;
    PVOID pTargetFunction = NULL;
    PRUNTIME_FUNCTION pRuntimeFunction = NULL;
    PUNWIND_HISTORY_TABLE pHistoryTable = NULL;
    DWORD64 ImageBase = 0;
    void* targetFunctionStart = NULL;
    void* targetFunctionEnd = NULL;

    // [1] Resolve target function.
    hModule = GetModuleHandleA(targetModule.c_str());
    if (!hModule)
    {
        goto Cleanup;
    }
    pTargetFunction = GetProcAddress(hModule, targetFunction.c_str());
    if (!pTargetFunction)
    {
        goto Cleanup;
    }

    // [2] Find function limits.
    pRuntimeFunction = RtlLookupFunctionEntry(
        (DWORD64)pTargetFunction,
        &ImageBase,
        pHistoryTable);
    if (!pRuntimeFunction)
    {
        goto Cleanup;
    }

    // [3] Check if given pointer is within range.
    targetFunctionStart = (PCHAR)hModule + pRuntimeFunction->BeginAddress;
    targetFunctionEnd = (PCHAR)hModule + pRuntimeFunction->EndAddress;
    if ((targetAddress > targetFunctionStart) && (targetAddress < targetFunctionEnd))
    {
        bAddressIsWithinTargetFunc = TRUE;
    }

Cleanup:
    return bAddressIsWithinTargetFunc;
}

//
// Takes an address in a remote process and re-maps it to the local process.
//
NTSTATUS NormalizeAddress(const HANDLE hProcess, const PVOID remoteAddress, PVOID& localAddress, const BOOL bIgnoreExe, const imageMap& imageBaseMap = imageMap())
{
    NTSTATUS status = STATUS_SUCCESS;

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    std::string moduleName;
    HMODULE hModule = NULL;
    ULONG64 offset = 0;

    // [1] Query pages at target address.
    if (!VirtualQueryEx(hProcess, (PVOID)remoteAddress, &mbi, sizeof(mbi)))
    {
        std::cout << "    [-] VirtualQueryEx failed\n";
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }
    // Calculate offset of return address.
    offset = (PCHAR)remoteAddress - (PCHAR)mbi.AllocationBase;

    // [2] Try and resolve module at address.
    if (!NT_SUCCESS(GetModuleBaseNameWrapper(hProcess, mbi.AllocationBase, moduleName)))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }
    std::cout << "    [+] Module at ret address is: " << moduleName << "\n";

    // [3] Some matching call stacks will have .exe's in them (e.g. taskhostw.exe).
    // This could look weird in a different process so ignore them here.
    if (bIgnoreExe)
    {
        if ((moduleName.find(".exe") != std::string::npos) || (moduleName.find(".EXE") != std::string::npos))
        {
            std::cout << "    [!] Found executable in call stack so rejecting: " << moduleName << "\n";
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }
    }

    // [4] If we can't get a handle, load Dll.
    hModule = GetModuleHandleA(moduleName.c_str());
    if (NULL == hModule)
    {
        std::cout << "    [+] Loading Library: " << moduleName.c_str() << "\n";
        // NB This uses standard search strategy as opposed to full path
        // so may fail and could be more robust (say by using GetMappedFileName)
        // e.g. clr.dll most obvious example of this.
        hModule = LoadLibraryA(moduleName.c_str());
        if (NULL == hModule)
        {
            std::cout << "    [-] Failed to load dll: " << moduleName << "\n";
            status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }
        // Add to map so that if we fail later on in the stack unwinding
        // process we can unload any dlls no longer needed.
        (const_cast<imageMap&>(imageBaseMap)).insert({ moduleName, hModule });
    }
    localAddress = (PCHAR)hModule + offset;

Cleanup:
    return status;
}

//
// Walks the call stack of the target thread and calculates its total size.
//
NTSTATUS CalculateDynamicStackSize(const HANDLE hProcess, const CONTEXT ctx, ULONG& totalStackSize)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    PVOID returnAddress = NULL;
    PVOID previousReturnAddress = NULL;
    PVOID currentChildSP = NULL;
    PVOID stackIndex = NULL;
    BOOL bHandledFirstFrame = FALSE;
    BOOL bFinishedUnwinding = FALSE;
    imageMap imageBaseMap = {};

    currentChildSP = (PVOID)ctx.Rsp;
    stackIndex = (PVOID)ctx.Rsp;
    std::cout << "    [+] Child-SP: 0x" << std::hex << currentChildSP << "\n";

    // [1] Start unwinding the target thread stack.
    while (!bFinishedUnwinding)
    {
        // NB This is a *very* lightweight/hackerman method of unwinding a stack which
        // makes an assumption about the state of the target thread (i.e. it is waiting).
        if (!bHandledFirstFrame)
        {
            // We need to handle the first frame, which we assume
            // will be an ntdll wait function.
            returnAddress = (PVOID)ctx.Rip;
            bHandledFirstFrame = TRUE;
        }
        else
        {
            // [2] Retrieve the ret address at current stack index.
            previousReturnAddress = returnAddress;
            returnAddress = readProcessMemory<PVOID>(hProcess, (LPVOID)stackIndex);
            std::cout << "    [+] RetAddr: 0x" << std::hex << returnAddress << "\n";
            std::cout << "    [+] Child-SP: " << std::hex << currentChildSP << "\n";
        }

        // [3] Windows unwinds until it finds ret address of 0x0
        // so if this is true we have finished unwinding the stack.
        if (returnAddress == 0x0)
        {
            // For unknown reasons (exception handlers?) the basic stack unwinding functionality
            // in this PoC seems to have problems handling dbg related functionality
            // (e.g. DbgX.Shell.exe / corecrl.dll / Enghost.exe / dbgeng.dll..).
            // Therefore, as a sanity check, make sure the last address is ntdll!RtlUserThreadStart
            // before reporting success.
            if (!CheckIfAddressIsWithinTargetFunc(previousReturnAddress, "ntdll", "RtlUserThreadStart"))
            {
                std::cout << "    [-] Failed to unwind stack properly\n";
                goto Cleanup;
            }
            // NB If you comment out the status below you can enumerate all the thread stacks in the desired state.
            status = STATUS_SUCCESS;
            bFinishedUnwinding = TRUE;
        }
        else
        {
            StackFrame targetFrame = {};
            PRUNTIME_FUNCTION pRuntimeFunction = NULL;
            PUNWIND_HISTORY_TABLE pHistoryTable = NULL;
            DWORD64 ImageBase = 0;
            ULONG functionStackSize = 0;

            // [4] Normalize address so it is valid in context of local process.
            if (!NT_SUCCESS(NormalizeAddress(hProcess, returnAddress, targetFrame.returnAddress, TRUE, imageBaseMap)))
            {
                std::cout << "    [-] Failed to normalize remote address\n";
                goto Cleanup;
            }

            // [5] Calculate function size.
            pRuntimeFunction = RtlLookupFunctionEntry(
                (DWORD64)targetFrame.returnAddress,
                &ImageBase,
                pHistoryTable);
            if (!NT_SUCCESS(CalculateFunctionStackSize(pRuntimeFunction, ImageBase, targetFrame)))
            {
                std::cout << "    [-] Failed to calculate function stack size\n";
                goto Cleanup;
            }

            // [6] Increment total stack size count and record function stack size count.
            totalStackSize += targetFrame.totalStackSize;
            functionStackSize = targetFrame.totalStackSize;

            // [7] Find next Child-SP.
            currentChildSP = (PCHAR)currentChildSP + functionStackSize;

            // [8] Find next return address.
            // Child-SP is value of rsp after stack prologue hence ret
            // address is pushed on immediately after.
            stackIndex = (PCHAR)currentChildSP - 0x8;
        }
    }

Cleanup:
    if (!NT_SUCCESS(status))
    {
        // If we failed for w/e reason, unload all the libraries we loaded.
        for (auto const& lib : imageBaseMap)
        {
            (void)FreeLibrary(lib.second);
        }
    }
    return status;
}

//
// Checks target thread to see if it is waiting in our desired wait method (e.g. UserRequest + WaitForSingleObjectEx).
//
BOOL IsThreadAMatch(const HANDLE hProcess, const DWORD pid, const DWORD tid, threadToSpoof& thread)
{
    BOOL bMatch = FALSE;

    HANDLE hThread = INVALID_HANDLE_VALUE;
    HANDLE hHeap = INVALID_HANDLE_VALUE;
    BOOL bIsWow64 = false;
    CONTEXT ctx = { 0 };

    PVOID returnAddress = NULL;
    PVOID remoteStartAddress = NULL;
    ULONG totalStackSize = 0;

    // [1] Open handle to thread.
    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!hThread)
    {
        std::cout << "[-] Failed to open a handle to thread: " << tid << "\n";
        goto Cleanup;
    }

    // [2] Get thread context.
    std::cout << "[+] Scanning tid: " << std::dec << tid << "\n";
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx))
    {
        std::cout << "[-] Failed to get thread context for: " << tid << "\n";
        goto Cleanup;
    }

    // [3] Retrieve the last return address on the stack and check if it is
    // our target function to spoof.
    returnAddress = readProcessMemory<PVOID>(hProcess, (LPVOID)ctx.Rsp);
    if (!CheckIfAddressIsWithinTargetFunc(returnAddress, targetWaitModule, targetWaitFunction))
    {
        goto Cleanup;
    }

    // [4] Now try and confirm we can unwind the stack and calculate total required stack size.
    if (!NT_SUCCESS(CalculateDynamicStackSize(hProcess, ctx, totalStackSize)))
    {
        goto Cleanup;
    }

    // [5] Lastly, we need to retrieve the threads starting address in order to spoof it.
    if (!NT_SUCCESS(GetThreadStartAddress(hThread, remoteStartAddress)))
    {
        std::cout << "[-] Error retrieving thread start address\n";
        goto Cleanup;
    }

    // [6] The start address is specific to context of remote process, so ensure the
    // offset is correct for wherever the dll is loaded in our memory space.
    if (!NT_SUCCESS(NormalizeAddress(hProcess, remoteStartAddress, thread.startAddr, FALSE)))
    {
        std::cout << "[-] Error re-calculating thread start address\n";
        goto Cleanup;
    }

    // [7] At this stage, the thread stack is a match so make a copy.
    // To simplify this PoC (and to avoid any TOCTOU style issues) copy the stack
    // now and use the same buffer repeatedly. NB this is currently never freed,
    // but it is irrelevant as PoC runs on while true loop.
    hHeap = GetProcessHeap();
    thread.pFakeStackBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, totalStackSize);
    if (!ReadProcessMemory(hProcess, (LPCVOID)ctx.Rsp, thread.pFakeStackBuffer, totalStackSize, NULL))
    {
        HeapFree(hHeap, NULL, thread.pFakeStackBuffer);
        thread.pFakeStackBuffer = NULL;
        goto Cleanup;
    }

    thread.dwPid = pid;
    thread.dwTid = tid;
    thread.totalRequiredStackSize = totalStackSize;

    bMatch = TRUE;

Cleanup:
    CloseHandle(hThread);
    return bMatch;
}

//
//  Enumerates threads across the system, locates one in a desired wait state, and copies its call stack.
//
// Based on: https://github.com/thefLink/Hunt-Sleeping-Beacons/blob/main/source/Hunt-Sleeping-Beacons.c
NTSTATUS InitialiseDynamicCallStackSpoofing(const ULONG waitReason, threadToSpoof& thread)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    ULONG uBufferSize = 0;
    PVOID pBuffer = NULL;
    pNtQuerySystemInformation myNtQuerySystemInformation = NULL;
    SYSTEM_PROCESS_INFORMATION* pSystemProcessInformation = NULL;
    SYSTEM_THREAD_INFORMATION systemThreadInformation = { 0 };

    // [1] Enumerate threads system wide and locate a thread with desired WaitReason.
    myNtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!myNtQuerySystemInformation)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }
    status = myNtQuerySystemInformation(SystemProcessInformation, pBuffer, uBufferSize, &uBufferSize);
    if (STATUS_INFO_LENGTH_MISMATCH != status)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }
    pBuffer = LocalAlloc(LMEM_FIXED, uBufferSize);
    if (!pBuffer)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }
    if (!NT_SUCCESS(myNtQuerySystemInformation(SystemProcessInformation, pBuffer, uBufferSize, &uBufferSize)))
    {
        status = STATUS_UNSUCCESSFUL;
        goto Cleanup;
    }
    pSystemProcessInformation = (SYSTEM_PROCESS_INFORMATION*)pBuffer;

    // [2] Loop over threads and attempt to find one where the last address on the
    // stack is located within out target waiting function (e.g. WaitForSingleObjectEx).
    while (pSystemProcessInformation && pSystemProcessInformation->NextEntryOffset)
    {
        BOOL bEnumThreads = true;
        HANDLE hProcess = INVALID_HANDLE_VALUE;
        BOOL bIsWow64 = false;

        if (NULL != pSystemProcessInformation->ImageName.Buffer)
        {
            std::wcout << "[+] Searching process: " << pSystemProcessInformation->ImageName.Buffer << " (" << pSystemProcessInformation->ProcessId << ")" << "\n";
        }

        // [3] Attempt to open a handle to target process.
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pSystemProcessInformation->ProcessId);
        if (!hProcess)
        {
            std::cout << "[-] Failed to open a handle to process: " << pSystemProcessInformation->ProcessId << "\n";
            bEnumThreads = false;
        }

        // [4] Ignore WOW64.
        if (bEnumThreads && IsWow64Process(hProcess, &bIsWow64))
        {
            if (bIsWow64)
            {
                std::cout << "[-] Ignoring WOW64\n";
                bEnumThreads = false;
            }
        }

        // [5] Enumerate threads.
        if (bEnumThreads)
        {
            for (ULONG i = 0; i < pSystemProcessInformation->NumberOfThreads; i++)
            {
                systemThreadInformation = pSystemProcessInformation->ThreadInfos[i];

                // Ignore any threads not in our desired wait state.
                if (waitReason != systemThreadInformation.WaitReason)
                {
                    continue;
                }

                // [6] Attempt to unwind the stack and check if stack is in our desired wait state.
                if (IsThreadAMatch(hProcess, pSystemProcessInformation->ProcessId, (DWORD)systemThreadInformation.ClientId.UniqueThread, thread))
                {
                    // We have found a thread to clone!
                    std::cout << "    [+] Successfully located a thread call stack to clone!" << "\n";
                    std::wcout << "    [+] Cloning call stack from process: " << pSystemProcessInformation->ImageName.Buffer << "\n";
                    std::cout << "    [+] Cloning call stack from pid: " << std::dec << pSystemProcessInformation->ProcessId << "\n";
                    std::cout << "    [+] Cloning call stack from tid: " << std::dec << (DWORD)systemThreadInformation.ClientId.UniqueThread << "\n";
                    std::cout << "    [+] Target thread start address is: 0x" << std::hex << thread.startAddr << "\n";
                    std::cout << "    [+] Total stack size required: 0x" << thread.totalRequiredStackSize << "\n";
                    status = STATUS_SUCCESS;
                    CloseHandle(hProcess);
                    goto Cleanup;
                }
            }
        }
        // Avoid leaking handles.
        if (hProcess)
        {
            CloseHandle(hProcess);
        }
        pSystemProcessInformation = (SYSTEM_PROCESS_INFORMATION*)((LPBYTE)pSystemProcessInformation + pSystemProcessInformation->NextEntryOffset);
    }

    // [7] If we reached here we did not find a suitable thread call stack to spoof.
    std::cout << "[!] Could not find a suitable callstack to clone.\n";

Cleanup:
    LocalFree(pBuffer);
    return status;
}

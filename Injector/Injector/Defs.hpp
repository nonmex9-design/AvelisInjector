// defines the shared data structures, function pointer types, status enums, and raw machine code that serve as the communication protocol and control panel between your injector and the remote hooks running inside Roblox.

#pragma once
#include <Windows.h>

using TNtSetInformationProcess = NTSTATUS(NTAPI*)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
using TRtlRestoreContext = void(__cdecl*)(PCONTEXT, EXCEPTION_RECORD*);
using THeartBeat = uintptr_t(__fastcall*)(uintptr_t, uintptr_t, uintptr_t);
using TLoadLibraryExA = HMODULE(__stdcall*)(LPCSTR, HANDLE, DWORD);
using TRtlAddFunctionTable = BOOLEAN(__cdecl*)(PRUNTIME_FUNCTION, DWORD, DWORD64);
using TLoadLibraryA = HMODULE(__stdcall*)(LPCSTR);
using TGetProcAddress = FARPROC(__stdcall*)(HMODULE, LPCSTR);

#define ProcessInstrumentationCallback 0x28
#define WriteShared(field, value) Write<decltype(Shared::field)>(sharedMemory + offsetof(Shared, field), value)

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

enum class Status {
    RegisterIC,
    Wait,
    InjectDLL,
    InjectedDLL,
};

struct Shared {
    THeartBeat OriginalHeartBeat;
    TLoadLibraryExA fLoadLibraryExA;
    TRtlRestoreContext fRtlRestoreContext;
    TNtSetInformationProcess fNtSetInformationProcess;
    TRtlAddFunctionTable fRtlAddFunctionTable;
    TLoadLibraryA fLoadLibraryA;
    TGetProcAddress fGetProcAddress;

    uintptr_t dllStart;
    uintptr_t dllEnd;
    uintptr_t dllEntryPoint;

    uintptr_t ExceptionVA;
    uintptr_t ExceptionSize;
    uintptr_t ImportVA;
    uintptr_t ImportSize;
    uintptr_t TLSVA;
    uintptr_t TLSSize;

    uintptr_t IC;
    uintptr_t HyperionBase;

    Status Status;
};

std::vector<BYTE> icWrapper = {
    0x65,0x48,0x89,0x24,0x25,0xE0,0x02,0x00,0x00,
    0x65,0x4C,0x89,0x14,0x25,0xD8,0x02,0x00,0x00,
    0x4C,0x8B,0xD1,
    0x48,0x81,0xEC,0xD0,0x04,0x00,0x00,
    0x48,0x83,0xE4,0xF0,
    0x48,0x8B,0xCC,
    0x49,0xBB,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x41,0xFF,0xD3,
    0x48,0x83,0xEC,0x20,
    0x49,0xBB,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x41,0xFF,0xD3,
    0x48,0x83,0xC4,0x20,
    0xC3,
};
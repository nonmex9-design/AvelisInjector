// made by 0x38 / Avelis.dev (@rocodeses)

#include <iostream>
#include <vector>
#include <filesystem>
#include "Memory/Memory.hpp"
#include "Mapper/Mapper.hpp"
#include "Defs.hpp"
#include "Offsets.hpp"

uintptr_t HeartbeatHook(uintptr_t a1, uintptr_t a2, uintptr_t a3) {
    auto shared = (Shared*)0x100000000;

    if (shared->Status == Status::RegisterIC) {
        shared->Status = Status::Wait;

        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana = {};
        nirvana.Callback = (PVOID)shared->IC;
        nirvana.Reserved = 0;
        nirvana.Version = 0;

        shared->fNtSetInformationProcess((HANDLE)-1, (PROCESS_INFORMATION_CLASS)ProcessInstrumentationCallback, &nirvana, sizeof(nirvana));

        char mshtml[] = { 'm', 's', 'h', 't', 'm', 'l', '.', 'd', 'l', 'l', '\0' };
        shared->fLoadLibraryExA(mshtml, NULL, DONT_RESOLVE_DLL_REFERENCES);
    }

    if (shared->Status == Status::InjectDLL) {
        uintptr_t dllStart = shared->dllStart;
        uintptr_t exVA = shared->ExceptionVA;
        uintptr_t exSize = shared->ExceptionSize;

        if (exVA && exSize) {
            RUNTIME_FUNCTION* table = (RUNTIME_FUNCTION*)(dllStart + exVA);
            DWORD count = (DWORD)(exSize / sizeof(RUNTIME_FUNCTION));
            shared->fRtlAddFunctionTable(table, count, (DWORD64)dllStart);
        }

        PIMAGE_IMPORT_DESCRIPTOR importStart = (PIMAGE_IMPORT_DESCRIPTOR)(dllStart + shared->ImportVA);
        PIMAGE_IMPORT_DESCRIPTOR importEnd = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)importStart + shared->ImportSize);

        while (importStart < importEnd && importStart->Name) {
            HMODULE loadedDLL = shared->fLoadLibraryA((char*)(dllStart + importStart->Name));
            if (!loadedDLL) {
                ++importStart;
                continue;
            }

            uintptr_t* thunk;
            if (!importStart->OriginalFirstThunk)
                thunk = (uintptr_t*)(dllStart + importStart->FirstThunk);
            else
                thunk = (uintptr_t*)(dllStart + importStart->OriginalFirstThunk);

            FARPROC* func = (FARPROC*)(dllStart + importStart->FirstThunk);

            for (; *thunk; ++thunk, ++func) {
                if (IMAGE_SNAP_BY_ORDINAL(*thunk))
                    *func = shared->fGetProcAddress(loadedDLL, MAKEINTRESOURCEA(IMAGE_ORDINAL(*thunk)));
                else {
                    IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(dllStart + *thunk);
                    *func = shared->fGetProcAddress(loadedDLL, importByName->Name);
                }
            }

            ++importStart;
        }

        if (shared->TLSVA != 0 && shared->TLSSize != 0) {
            IMAGE_TLS_DIRECTORY64* tlsDir = (IMAGE_TLS_DIRECTORY64*)(dllStart + shared->TLSVA);

            ULONGLONG rawCallbacks = tlsDir->AddressOfCallBacks;
            if (rawCallbacks != 0) {
                uintptr_t callbacksVA = (uintptr_t)rawCallbacks;
                if (callbacksVA < dllStart || callbacksVA >= shared->dllEnd)
                    callbacksVA = dllStart + (uintptr_t)rawCallbacks;

                PIMAGE_TLS_CALLBACK* cbList = (PIMAGE_TLS_CALLBACK*)callbacksVA;

                for (size_t i = 0;; ++i) {
                    PIMAGE_TLS_CALLBACK callback = cbList[i];
                    if (callback == nullptr)
                        break;

                    callback((PVOID)dllStart, DLL_PROCESS_ATTACH, nullptr);
                }
            }
        }

        auto dllMain = (BOOL(__stdcall*)(HMODULE, DWORD, LPVOID))(shared->dllEntryPoint);
        dllMain((HMODULE)shared->dllStart, DLL_PROCESS_ATTACH, 0);

        shared->Status = Status::InjectedDLL;
    }

    return shared->OriginalHeartBeat(a1, a2, a3);
}

static uintptr_t GetIATAddress(uintptr_t moduleBase, const char* funcName) {
    auto dosHeader = Read<IMAGE_DOS_HEADER>(moduleBase);
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    auto ntHeaders = Read<IMAGE_NT_HEADERS>(moduleBase + dosHeader.e_lfanew);
    auto importDir = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0) return 0;

    uintptr_t importDescVA = moduleBase + importDir.VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR desc;
    do {
        if (!Read(importDescVA, &desc, sizeof(desc))) break;
        if (desc.Name == 0) break;
        char dllName[256];
        if (!Read(moduleBase + desc.Name, dllName, sizeof(dllName))) break;
        if (_stricmp(dllName, "ntdll.dll") != 0) {
            importDescVA += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            continue;
        }
        uintptr_t thunkVA = moduleBase + desc.FirstThunk;
        uintptr_t origThunkVA = moduleBase + desc.OriginalFirstThunk;
        for (;;) {
            uintptr_t thunk = Read<uintptr_t>(origThunkVA);
            if (thunk == 0) break;
            if (!(thunk & IMAGE_ORDINAL_FLAG64)) {
                uintptr_t nameVA = moduleBase + (thunk + 2);
                char name[256];
                if (Read(nameVA, name, sizeof(name)) && strcmp(name, funcName) == 0) {
                    return moduleBase + desc.FirstThunk + (origThunkVA - (moduleBase + desc.OriginalFirstThunk));
                }
            }
            origThunkVA += sizeof(uintptr_t);
            thunkVA += sizeof(uintptr_t);
        }
        importDescVA += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    } while (desc.Name != 0);

    return 0;
}

void __stdcall InstrumentationCallback(PCONTEXT ctx) {
    auto shared = (Shared*)0x100000000;
    uint64_t currentTeb = (uint64_t)NtCurrentTeb();
    ctx->Rip = *(uint64_t*)(currentTeb + 0x02d8);
    ctx->Rsp = *(uint64_t*)(currentTeb + 0x02e0);

    static uintptr_t ntUnmapIAT = 0;
    if (ntUnmapIAT == 0) {
        ntUnmapIAT = GetIATAddress(shared->HyperionBase, "NtUnmapViewOfSection");
        if (ntUnmapIAT == 0) ntUnmapIAT = shared->HyperionBase + 0xD8E428;
    }

    if (ctx->Rip == ntUnmapIAT) {
        *(uintptr_t*)(ctx->Rbp + 0xA3D0) = 0;
    }

    ctx->Rcx = ctx->R10;
    ctx->R10 = 0;

    shared->fRtlRestoreContext(ctx, nullptr);
}

static uintptr_t GetExportRVA(PBYTE dllBuffer, const char* funcName) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBuffer;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(dllBuffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0) return 0;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(dllBuffer + exportRVA);
    DWORD* nameRVAs = (DWORD*)(dllBuffer + exportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(dllBuffer + exportDir->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)(dllBuffer + exportDir->AddressOfFunctions);
    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
        const char* name = (const char*)(dllBuffer + nameRVAs[i]);
        if (strcmp(name, funcName) == 0) {
            return funcRVAs[ordinals[i]];
        }
    }
    return 0;
}

int main() {
    auto AvelisDLL = (std::filesystem::current_path() / "Avelis.dll").string();
    if (!std::filesystem::exists(AvelisDLL)) {
        std::cout << "invalid DLL path\n";
        getchar();
        exit(0);
    }

    DWORD pid = GetPID("RobloxPlayerBeta.exe");
    if (!pid) {
        std::cout << "Failed to get the PID of Roblox.\n";
        getchar();
        exit(0);
    }

    pHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!pHandle) {
        std::cout << "Failed to open a Handle to Roblox.\n";
        getchar();
        exit(0);
    }

    uintptr_t devenumBase = (uintptr_t)GetModuleEntry(pid, "devenum.dll").modBaseAddr;
    uintptr_t icWrapperBase = devenumBase + 0x300;
    uintptr_t icBase = devenumBase + 0x400;

    Protect(devenumBase, 0x1000, PAGE_EXECUTE_READWRITE);
    std::vector<BYTE> zeros(0x1000, 0);
    Write(devenumBase, zeros.data(), zeros.size());

    uintptr_t robloxBase = (uintptr_t)GetModuleEntry(pid, "RobloxPlayerBeta.exe").modBaseAddr;
    uintptr_t hyperionBase = (uintptr_t)GetModuleEntry(pid, "RobloxPlayerBeta.dll").modBaseAddr;
    uintptr_t kernelBase = (uintptr_t)GetModuleEntry(pid, "KERNELBASE.dll").modBaseAddr;
    uintptr_t kernel32 = (uintptr_t)GetModuleEntry(pid, "KERNEL32.dll").modBaseAddr;
    uintptr_t ntDLL = (uintptr_t)GetModuleEntry(pid, "ntdll.dll").modBaseAddr;

    uintptr_t fRtlCaptureContext = GetModuleProc(ntDLL, "RtlCaptureContext");

    uintptr_t jobs = Read<uintptr_t>(Read<uintptr_t>(robloxBase + Offsets::TaskSchedulerPointer) + Offsets::TaskSchedulerToJobs);
    uintptr_t heartBeatJob = GetHeartBeat(jobs);
    uintptr_t originalVTable = Read<uintptr_t>(heartBeatJob);
    uintptr_t originalHeartBeat = Read<uintptr_t>(originalVTable + 0x8);

    uintptr_t newVTable = (uintptr_t)VirtualAllocEx(pHandle, 0, 0x300, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    for (uintptr_t i = 0x0; i < 0x300; i += 0x8)
        Write<uintptr_t>(newVTable + i, Read<uintptr_t>(originalVTable + i));

    Write<uintptr_t>(newVTable + 0x8, devenumBase);

    sharedMemory = (uintptr_t)VirtualAllocEx(pHandle, 0, sizeof(Shared), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    std::vector<BYTE> shellcode = ExtractShellcode((uintptr_t)HeartbeatHook);
    std::vector<BYTE> icShellcode = ExtractShellcode((uintptr_t)InstrumentationCallback);
    ReplaceShellcode(shellcode, 0x100000000, sharedMemory);
    ReplaceShellcode(icShellcode, 0x100000000, sharedMemory);

    Write(devenumBase, shellcode.data(), shellcode.size());

    std::cout << "HeartBeat = 0x" << std::hex << heartBeatJob << "\n";

    Shared localView = {};
    localView.HyperionBase = hyperionBase;
    localView.OriginalHeartBeat = (THeartBeat)originalHeartBeat;
    localView.fLoadLibraryExA = (TLoadLibraryExA)GetModuleProc(kernelBase, "LoadLibraryExA");
    localView.fRtlRestoreContext = (TRtlRestoreContext)GetModuleProc(ntDLL, "RtlRestoreContext");
    localView.fNtSetInformationProcess = (TNtSetInformationProcess)GetModuleProc(ntDLL, "NtSetInformationProcess");
    localView.fLoadLibraryA = (TLoadLibraryA)GetModuleProc(kernelBase, "LoadLibraryA");
    localView.fGetProcAddress = (TGetProcAddress)GetModuleProc(kernel32, "GetProcAddress");
    localView.fRtlAddFunctionTable = (TRtlAddFunctionTable)GetModuleProc(ntDLL, "RtlAddFunctionTable");
    localView.IC = icWrapperBase;

    Write(sharedMemory, &localView, sizeof(Shared));

    memcpy(&icWrapper[37], &fRtlCaptureContext, sizeof(fRtlCaptureContext));
    memcpy(&icWrapper[54], &icBase, sizeof(icBase));

    Write(icWrapperBase, icWrapper.data(), icWrapper.size());
    Write(icBase, icShellcode.data(), icShellcode.size());

    Write<uintptr_t>(heartBeatJob, newVTable);
    std::cout << "HeartBeat Hooked\n";

    MODULEENTRY32 mshtmlEntry = {};
    do {
        mshtmlEntry = GetModuleEntry(pid, "mshtml.dll");
        Sleep(1);
    } while ((uintptr_t)mshtmlEntry.modBaseAddr == 0);

    uintptr_t mshtmlBase = (uintptr_t)mshtmlEntry.modBaseAddr;

    Protect(mshtmlBase, mshtmlEntry.modBaseSize, PAGE_EXECUTE_READWRITE);
    zeros = std::vector<BYTE>(mshtmlEntry.modBaseSize);
    Write(mshtmlBase, zeros.data(), zeros.size());

    dllBase = mshtmlBase;
    dllSize = GetDLLSize(AvelisDLL);
    WriteShared(dllStart, mshtmlBase);
    WriteShared(dllEnd, mshtmlBase + dllSize);

    Mapper::Map(AvelisDLL);
    Mapper::Inject();

    std::ifstream dllFile(AvelisDLL, std::ios::binary | std::ios::ate);
    std::streampos fileSize = dllFile.tellg();
    std::vector<BYTE> dllBuffer(fileSize);
    dllFile.seekg(0, std::ios::beg);
    dllFile.read((char*)dllBuffer.data(), fileSize);
    dllFile.close();

    uintptr_t initRVA = GetExportRVA(dllBuffer.data(), "InitializeAvelis");
    if (initRVA) {
        uintptr_t remoteInit = dllBase + initRVA;
        std::cout << "InitializeAvelis at remote address 0x" << std::hex << remoteInit << "\n";
        HANDLE hThread = CreateRemoteThread(pHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteInit, nullptr, 0, nullptr);
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            DWORD exitCode;
            GetExitCodeThread(hThread, &exitCode);
            std::cout << "InitializeAvelis thread exited with code " << std::dec << exitCode << "\n";
            CloseHandle(hThread);
        }
        else {
            std::cout << "Failed to create remote thread for InitializeAvelis\n";
        }
    }
    else {
        std::cout << "InitializeAvelis export not found in DLL\n";
    }

    Write<uintptr_t>(heartBeatJob, originalVTable);
    std::cout << "Unhooked HeartBeat\n";
    std::cout << "Press Enter to exit...\n";
    getchar();

    return 0;
}
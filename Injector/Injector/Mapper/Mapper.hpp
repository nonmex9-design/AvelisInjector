// manually loads Avelis's DLL / module into Roblox by copying its sections, fixing addresses, and triggering its entry point—all without using LoadLibrary.

#pragma once
#include <fstream>
#include <filesystem>
#include "../Memory/Memory.hpp"
#include "../Defs.hpp"

std::string AvelisDLL;

uintptr_t sharedMemory;
uintptr_t dllSize;
uintptr_t dllBase;

void WaitFor(Status status) {
    do {
        Sleep(1);
    } while (Read<Status>(sharedMemory + offsetof(Shared, Status)) != status);
}

uintptr_t RVAVA(uintptr_t RVA, PIMAGE_NT_HEADERS NtHeaders, uint8_t* RawData)
{
    PIMAGE_SECTION_HEADER FirstSection = IMAGE_FIRST_SECTION(NtHeaders);
    for (PIMAGE_SECTION_HEADER Section = FirstSection; Section < FirstSection + NtHeaders->FileHeader.NumberOfSections; Section++)
        if (RVA >= Section->VirtualAddress && RVA < Section->VirtualAddress + Section->Misc.VirtualSize)
            return (uintptr_t)RawData + Section->PointerToRawData + (RVA - Section->VirtualAddress);

    return NULL;
}

BOOL RelocateImage(uintptr_t p_remote_img, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
    struct reloc_entry
    {
        ULONG to_rva;
        ULONG size;
        struct
        {
            WORD offset : 12;
            WORD type : 4;
        } item[1];
    };

    uintptr_t delta_offset = p_remote_img - nt_head->OptionalHeader.ImageBase;
    if (!delta_offset) return true; else if (!(nt_head->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return false;
    reloc_entry* reloc_ent = (reloc_entry*)RVAVA(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_head, (uint8_t*)p_local_img);
    uintptr_t reloc_end = (uintptr_t)reloc_ent + nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (reloc_ent == nullptr)
        return true;

    while ((uintptr_t)reloc_ent < reloc_end && reloc_ent->size)
    {
        DWORD records_count = (reloc_ent->size - 8) >> 1;
        for (DWORD i = 0; i < records_count; i++)
        {
            WORD fix_type = (reloc_ent->item[i].type);
            WORD shift_delta = (reloc_ent->item[i].offset) % 4096;

            if (fix_type == IMAGE_REL_BASED_ABSOLUTE)
                continue;

            if (fix_type == IMAGE_REL_BASED_HIGHLOW || fix_type == IMAGE_REL_BASED_DIR64)
            {
                uintptr_t fix_va = (uintptr_t)RVAVA(reloc_ent->to_rva, nt_head, (uint8_t*)p_local_img);

                if (!fix_va)
                    fix_va = (uintptr_t)p_local_img;

                *(uintptr_t*)(fix_va + shift_delta) += delta_offset;
            }
        }

        reloc_ent = (reloc_entry*)((LPBYTE)reloc_ent + reloc_ent->size);
    }

    return true;
}

namespace Mapper {
    void Map(std::string);
    void Inject();
}

SIZE_T GetDLLSize(const std::filesystem::path& filePath) {
    std::ifstream f(filePath, std::ios::binary);
    if (!f.is_open())
        return 0;

    IMAGE_DOS_HEADER dos = {};
    f.read((char*)&dos, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    IMAGE_NT_HEADERS nt = {};

    f.seekg(dos.e_lfanew, std::ios::beg);
    f.read((char*)&nt, sizeof(nt));

    if (nt.Signature != IMAGE_NT_SIGNATURE)
        return 0;

    return nt.OptionalHeader.SizeOfImage;
}

void Mapper::Map(std::string path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    std::streampos fileSize = file.tellg();
    if (fileSize <= 0) {
        file.close();
        return;
    }

    PBYTE buffer = (PBYTE)malloc(fileSize);
    if (buffer == nullptr) {
        file.close();
        return;
    }

    file.seekg(0, std::ios::beg);
    file.read((char*)buffer, fileSize);
    file.close();

    PIMAGE_NT_HEADERS ntHeader = (IMAGE_NT_HEADERS*)(buffer + ((IMAGE_DOS_HEADER*)buffer)->e_lfanew);
    PIMAGE_OPTIONAL_HEADER optionalHeader = &ntHeader->OptionalHeader;
    PIMAGE_FILE_HEADER fileHeader = &ntHeader->FileHeader;

    uintptr_t entryPoint = dllBase + optionalHeader->AddressOfEntryPoint;
    auto tls = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    auto import = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    WriteShared(TLSVA, tls.VirtualAddress);
    WriteShared(TLSSize, tls.Size);
    WriteShared(ImportVA, import.VirtualAddress);
    WriteShared(ImportSize, import.Size);
    WriteShared(dllEntryPoint, entryPoint);

    if (!RelocateImage(dllBase, buffer, ntHeader)) {
        std::cout << "Failed to relocate dll\n";
        free(buffer);
        return;
    }

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);

    for (UINT i = 0; i < fileHeader->NumberOfSections; ++i, ++sectionHeader) {
        if (sectionHeader->SizeOfRawData == 0 || (sectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
            continue;

        LPVOID targetAddress = (LPVOID)(dllBase + sectionHeader->VirtualAddress);
        PBYTE sourceData = buffer + sectionHeader->PointerToRawData;
        SIZE_T dataSize = sectionHeader->SizeOfRawData;

        SIZE_T written = 0;
        if (!WriteProcessMemory(pHandle, targetAddress, sourceData, dataSize, &written) || written != dataSize) {
            std::cout << "Failed to write section: " << sectionHeader->Name << ". Error: " << GetLastError() << "\n";
            continue;
        }

        if (sectionHeader->Misc.VirtualSize > dataSize) {
            uintptr_t zeroStart = dllBase + sectionHeader->VirtualAddress + dataSize;
            SIZE_T zeroSize = sectionHeader->Misc.VirtualSize - dataSize;
            std::vector<BYTE> zeros(zeroSize, 0);
            Write(zeroStart, zeros.data(), zeroSize);
        }

        DWORD protect = PAGE_READWRITE;
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protect = (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        }
        else if (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        }
        else {
            protect = PAGE_READONLY;
        }
        VirtualProtectEx(pHandle, targetAddress, sectionHeader->Misc.VirtualSize, protect, &oldP);
    }

    IMAGE_DATA_DIRECTORY exceptions = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    if (exceptions.Size) {
        WriteShared(ExceptionVA, exceptions.VirtualAddress);
        WriteShared(ExceptionSize, exceptions.Size);
    }

    free(buffer);
}

void Mapper::Inject() {
    std::cout << "Waiting for hook\n";

    WriteShared(Status, Status::InjectDLL);
    WaitFor(Status::InjectedDLL);

    std::cout << "Injected\n";
}
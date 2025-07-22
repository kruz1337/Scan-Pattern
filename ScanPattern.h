/*
              ____                             __ _  __    ____
             / __ \___  ____ ___  _____  _____/ /| |/ /   / __ \___ _   __
            / /_/ / _ \/ __ `/ / / / _ \/ ___/ __|   /   / / / / _ | | / /
           / _, _/  __/ /_/ / /_/ /  __(__  / /_/   |   / /_/ /  __| |/ _
          /_/ |_|\___/\__, /\__,_/\___/____/\__/_/|_|  /_____/\___/|___(_)

                        Developed by github.com/kruz1337
*/

#pragma once

#include <windows.h>
#include <string.h>
#include <psapi.h>
#include <tlhelp32.h>

#define READ_LENGTH 8192

namespace ScanPattern {
    inline bool ScanSubBytes(unsigned int* destIndex, unsigned char* src, unsigned char* pattern, unsigned int srcSize, unsigned int patternSize = NULL, const char* mask = NULL) {
        if (patternSize > srcSize) {
            printf("[-] Pattern can't be higher than source.");
            return false;
        }

        unsigned int found = 0, index = 0;
        unsigned int byteSize = patternSize ? patternSize : strlen(mask);

        for (int i = 0; i < srcSize; i++) {
            if (found == byteSize) {
                index = i;
                break;
            }

            if (pattern[found] != src[i] && (mask == NULL || mask[found] != '?')) {
                found = 0;
                continue;
            }

            ++found;
        }

        if (index == 0) {
            return false;
        }

        *destIndex = (index-byteSize);
        return true;
    }

    inline bool ParseBytes(const char* src, unsigned char** bytes, unsigned int* bytesSize) {
        if (!src || src[0] == '\0') {
            printf("[-] Invalid source.");
            return false;
        }

        char* dupByte = strdup(src);
        char* byte = strtok(dupByte, " ");
        unsigned char* bufferBytes = (unsigned char*)calloc(1, sizeof(unsigned char));

        unsigned int index = 0;
        while (byte != NULL) {
            bufferBytes[index] = strtol(byte, NULL, 16);
            ++index;
            bufferBytes = (unsigned char*)realloc(bufferBytes, sizeof(unsigned char) * 1+index);
            byte = strtok(NULL, " ");
        }

        if (index == 0 || bufferBytes == NULL) {
            return false;
        }

        *bytesSize = index;
        *bytes = bufferBytes;

        return true;
    }

    inline bool RvaToFileOffset(const char* file, ULONG_PTR rva, ULONG_PTR* offset) {
        FILE* fp = fopen(file, "r+b");
        if (fp == NULL) {
            printf("[-] Failed to open file: '%s'\n", file);
            return false;
        }

        if (rva == NULL) {
            printf("[-] Invalid address.\n");
            return false;
        }

        IMAGE_DOS_HEADER dosHeader;
        IMAGE_NT_HEADERS ntHeader;

        fread(&dosHeader, sizeof(IMAGE_DOS_HEADER), 1, fp);

        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            printf("[-] Invalid DOS Header.\n");
            return false;
        }

        fseek(fp, dosHeader.e_lfanew, SEEK_SET);
        fread(&ntHeader, sizeof(IMAGE_NT_HEADERS), 1, fp);

        if (ntHeader.Signature != IMAGE_NT_SIGNATURE) {
            printf("[-] Invalid NT Header.\n");
            return false;
        }

        IMAGE_SECTION_HEADER sectionHeader;
        long fileOffset = NULL;

        for (int i = 0; i < ntHeader.FileHeader.NumberOfSections; i++) {
            fread(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), 1, fp);
            auto rebasedOffset = rva > ntHeader.OptionalHeader.ImageBase ? rva - ntHeader.OptionalHeader.ImageBase : rva;

            if (rebasedOffset < (sectionHeader.VirtualAddress + sectionHeader.SizeOfRawData)) {
                fileOffset = (rebasedOffset - sectionHeader.VirtualAddress) + sectionHeader.PointerToRawData;
                break;
            }
        }

        if (fileOffset == NULL) {
            printf("[-] Invalid rva offset.\n");
            return false;
        }

        *offset = fileOffset;
        fclose(fp);

        return true;
    }

    inline bool ParsePattern(const char* src, unsigned char** pattern, char** mask) {
        if (!src || src[0] == '\0') {
            printf("[-] Invalid source pattern.\n");
            return false;
        }

        char* dupByte = strdup(src);
        char* byte = strtok(dupByte, " ");

        unsigned int maskSize = 0;
        unsigned char* patternBuffer= (unsigned char*)malloc(1 * sizeof(char));
        char* maskBuffer = (char*)malloc(1 * sizeof(char));

        while (byte != NULL) {
            patternBuffer = (unsigned char*)realloc(patternBuffer, (maskSize+1) * sizeof(unsigned char));
            maskBuffer = (char*)realloc(maskBuffer, (maskSize+1) * sizeof(unsigned char));

            patternBuffer[maskSize] = (strcmp(byte, "??") == 0 || strcmp(byte, "?") == 0) ? 0 : strtol(byte, NULL, 16);
            maskBuffer[maskSize] = (strcmp(byte, "??") == 0 || strcmp(byte, "?") == 0) ? '?' : 'x';

            maskSize++;
            byte = strtok(NULL, " ");
        }

        maskBuffer[maskSize] = '\0';

        if (maskSize == 0 || (maskBuffer == NULL || maskBuffer[0] == '\0')) {
            printf("[-] Failed to convert pattern.\n");
            return false;
        }

        *mask = maskBuffer;
        *pattern = patternBuffer;

        return true;
    }

    inline bool GetModuleInfoByName(HANDLE processHandle, const char* moduleName, MODULEINFO* outModuleInfo) {
        if (moduleName == NULL || moduleName[0] == '\0') {
            printf("[-] Invalid module name.\n");
            return false;
        }

        if (!processHandle) {
            printf("[-] Invalid process handle.\n");
            return false;
        }

        HMODULE modules[1024];
        unsigned long modulesSize = 0;

        if (!EnumProcessModulesEx(processHandle, modules, sizeof(modules), &modulesSize, LIST_MODULES_ALL)) {
            printf("[-] Failed to enumerate process modules.\n");
            return false;
        }

        MODULEINFO moduleInfo;
        unsigned int moduleIndex = 0;

        for (int i = 0; i < modulesSize / sizeof(HMODULE); i++) {
            char baseName[512];
            GetModuleBaseName(processHandle, modules[i], baseName, sizeof(baseName) / sizeof(baseName[0]));

            if (strcmp(baseName, moduleName) == 0) {
                moduleIndex = i;
                break;
            }
        }

        if (moduleIndex == 0 ||
            !GetModuleInformation(processHandle, modules[moduleIndex], &moduleInfo, sizeof(MODULEINFO))) {
            return false;
        }

        *outModuleInfo = moduleInfo;
        return true;
    }

    inline bool GetProcessIdByName(const char* processName, DWORD* outProcessId){
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to create snapshot.\n");
            return false;
        }

        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(snapshot, &processEntry)) {
            printf("[-] Failed to get first process.\n");
            return false;
        }

        DWORD processId = 0;
        do {
            if (strcmp(processEntry.szExeFile, processName) == 0) {
                processId = processEntry.th32ProcessID;
                break;
            }
        }
        while (Process32Next(snapshot, &processEntry));

        if (processId == 0) {
            return false;
        }

        *outProcessId = processId;

        return true;
    }

    inline bool FileScanPatternString(ULONG_PTR* offset, const char* file, unsigned char* pattern, unsigned int patternSize = NULL, const char* mask = NULL) {
        if (pattern == NULL) {
            printf("[-] Invalid pattern.\n");
            return false;
        }

        FILE *fp = fopen(file, "rb");
        if (fp == NULL) {
            printf("[-] Failed to open file: '%s'\n", file);
            return false;
        }

        ULONG_PTR byteReadCount = READ_LENGTH * (((patternSize ? patternSize : strlen(mask)) + READ_LENGTH - 1) / READ_LENGTH);
        ULONG_PTR byteReadSize = 0, tailReadSize = 0;
        unsigned char byteCombo[byteReadCount], byteBuffer[byteReadCount*2], *tailBytes;

        unsigned int destIndex = 0;
        while ((byteReadSize = fread(&byteCombo, sizeof(unsigned char), byteReadCount, fp)) != NULL) {
            memcpy(byteBuffer, tailBytes, tailReadSize);
            memcpy(byteBuffer+tailReadSize, byteCombo, byteReadSize);

            if (ScanSubBytes(&destIndex, byteBuffer, pattern, (byteReadSize + tailReadSize), patternSize, mask)) {
                *offset = ftell(fp) - ((byteReadSize+tailReadSize)-destIndex);
                break;
            }

            tailBytes = (unsigned char*)calloc(byteReadSize, sizeof(unsigned char));
            tailReadSize = byteReadSize;
            memcpy(tailBytes, byteCombo, byteReadSize);
        }

        if (destIndex == 0) {
            printf("[-] Failed to find offset.\n");
            return false;
        }

        fclose(fp);
        return true;
    }

    inline bool ScanPatternString(ULONG_PTR* offset, HANDLE processHandle, const char* moduleName, unsigned char* pattern, unsigned int patternSize = NULL, const char* mask = NULL) {
        if (pattern == NULL) {
            printf("[-] Invalid pattern.\n");
            return false;
        }

        if (processHandle == NULL) {
            printf("[-] Failed to open process handle.\n");
            return false;
        }

        MODULEINFO moduleInfo;
        if (!GetModuleInfoByName(processHandle, moduleName, &moduleInfo)) {
            printf("[-] Failed to get module information.\n");
            return false;
        }

        ULONG_PTR baseAddress = (ULONG_PTR)moduleInfo.lpBaseOfDll;
        ULONG_PTR moduleSize = moduleInfo.SizeOfImage;
        ULONG_PTR endAddress = baseAddress + moduleSize;

        ULONG_PTR byteReadCount = READ_LENGTH * (((patternSize ? patternSize : strlen(mask)) + READ_LENGTH - 1) / READ_LENGTH) ;
        ULONG_PTR byteReadSize = 0, tailReadSize = 0;
        unsigned char byteCombo[byteReadCount], byteBuffer[byteReadCount*2], *tailBytes;

        unsigned int destIndex = 0;
        for (ULONG_PTR currentAddress = baseAddress; currentAddress < endAddress; currentAddress += byteReadSize) {
            if (currentAddress + byteReadSize > endAddress) {
                byteReadCount = currentAddress - endAddress;
            }

            if (!ReadProcessMemory(processHandle, (LPCVOID)currentAddress, &byteCombo, byteReadCount, &byteReadSize)) {
                break;
            }

            memset(byteBuffer, 0, byteReadCount*2);
            memcpy(byteBuffer, tailBytes, tailReadSize);
            memcpy(byteBuffer+tailReadSize, byteCombo, byteReadSize);

            if (ScanSubBytes(&destIndex, byteBuffer, pattern, (byteReadSize + tailReadSize), patternSize, mask)) {
                *offset = (currentAddress - baseAddress) + (destIndex-byteReadCount);
                break;
            }

            tailBytes = (unsigned char*)calloc(byteReadSize, sizeof(unsigned char));
            tailReadSize = byteReadSize;
            memcpy(tailBytes, byteCombo, byteReadSize);
        }

        if (destIndex == 0) {
            printf("[-] Failed to find offset.\n");
            return false;
        }

        return true;
    }

    inline bool ScanPatternString(ULONG_PTR* offset, const char* moduleName, unsigned char* pattern, unsigned int patternSize = NULL, const char* mask = NULL) {
        return ScanPatternString(offset, GetCurrentProcess(), moduleName, pattern, patternSize, mask);
    }

    inline bool ScanPatternString(ULONG_PTR* offset, const char* processName, const char* moduleName, unsigned char* pattern, unsigned int patternSize = NULL, const char* mask = NULL) {
        if (processName == NULL || processName[0] == '\0') {
            printf("[-] Failed to find process name.\n");
            return false;
        }

        DWORD processId = 0;
        if (!GetProcessIdByName(processName, &processId)) {
            printf("[-] Failed to find process id.\n");
            return false;
        }

        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (processHandle == NULL) {
            printf("[-] Failed to open process handle.\n");
            return false;
        }

        return ScanPatternString(offset, processHandle, moduleName, pattern, patternSize, mask);
    }

    inline bool ScanPattern(ULONG_PTR* offset, HANDLE processHandle, const char* moduleName, const char* pattern) {
        unsigned char* patternBytes;
        unsigned int patternSize = NULL;
        char* patternMask = NULL;

        if (!ParsePattern(pattern, &patternBytes, &patternMask) && !ParseBytes(pattern, &patternBytes, &patternSize)) {
            printf("[-] Failed to parse pattern.\n");
            return false;
        }

        return ScanPatternString(offset, processHandle, moduleName, patternBytes, patternSize, patternMask);
    }

    inline bool ScanPattern(ULONG_PTR* offset, const char* moduleName, const char* pattern) {
        return ScanPattern(offset, GetCurrentProcess(), moduleName, pattern);
    }

    inline bool ScanPattern(ULONG_PTR* offset, const char* processName, const char* moduleName, const char* pattern) {
        if (processName == NULL || processName[0] == '\0') {
            printf("[-] Failed to find process name.\n");
            return false;
        }

        DWORD processId = 0;
        if (!GetProcessIdByName(processName, &processId)) {
            printf("[-] Failed to find process id.\n");
            return false;
        }

        HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (processHandle == NULL) {
            printf("[-] Failed to open process handle.\n");
            return false;
        }

        return ScanPattern(offset, processHandle, moduleName, pattern);
    }
}
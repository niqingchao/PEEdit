#include <Windows.h>
#pragma once

typedef union _IMAGE_OPTIONAL_HEADERS {
    IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
} IMAGE_OPTIONAL_HEADERS, * PIMAGE_OPTIONAL_HEADERS;

typedef struct {
    LPVOID pFileBuffer;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_FILE_HEADER pFileHeader;
    PIMAGE_OPTIONAL_HEADERS pOptionalHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;
    //IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} PEView;
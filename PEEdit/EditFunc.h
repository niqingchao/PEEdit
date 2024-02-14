#include <Windows.h>
#include <stdio.h>
#pragma once

size_t RvaToFoa64(LPVOID pBuffer, size_t dwRva);
size_t FoaToRva64(LPVOID pFileBuffer, size_t FOA);
int WritePEFile(PVOID pFileAddress, DWORD FileSize, LPSTR FilePath);
BOOL EditDosHeader(HWND hDlg, PIMAGE_DOS_HEADER pDosHeader);
#include <Windows.h>
#include <commctrl.h>
#include <stdio.h>
#include "EditFunc.h"
#include "MyStructs.h"
#include "resource.h"

HINSTANCE hIns;
HANDLE g_hOutput = 0;
BOOL bPE32 = FALSE; // 打开的是否为32位程序
BYTE* filePath = NULL;


PEView peView = { 0 };
PEView* pPeView = &peView;


// 打开文件路径，返回文件句柄
HANDLE OnOpen(HWND hWnd, WPARAM wParam, LPARAM lParam) {
    OPENFILENAME ofn;
    char szFile[260];
    HANDLE hf = NULL;
    // Initialize OPENFILENAME
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFile = szFile;
    // Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
    // use the contents of szFile to initialize itself.
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFile);

    ofn.lpstrFilter = TEXT("All\0*.*\0EXE\0*.EXE\0DLL\0*.DLL\0");
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    
    // Display the Open dialog box. 
    
    if (GetOpenFileName(&ofn) == TRUE)
        hf = CreateFile(ofn.lpstrFile,
            GENERIC_READ,
            0,
            (LPSECURITY_ATTRIBUTES)NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            (HANDLE)NULL);
    
    //MessageBox(hWnd, ofn.lpstrFile, TEXT("info"), MB_OK);
    filePath = malloc(strlen(ofn.lpstrFile));
    if (filePath != NULL){
        strcpy(filePath, ofn.lpstrFile);
    }
    else {
        filePath = TEXT("C:\\Users\\nqc\\Downloads\\demo.exe");
    }
    return hf;
}


int IsPEFile (PEView *pPeView, HANDLE hf) {
    DWORD fileSize;
    LPVOID lpFileImage;
    //2获取文件大小
    if (INVALID_FILE_SIZE == (fileSize = GetFileSize(hf, NULL)))
    {
        CloseHandle(hf);
        return FALSE;
    }
    //3在当期调用进程虚内存中申请空间
    if (!(lpFileImage = VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE)))
    {
        CloseHandle(hf);
        return FALSE;
    }
    //4把文件读取到指定的内存区域中
    DWORD dwRet = 0;
    if (!ReadFile(hf, lpFileImage, fileSize, &dwRet, NULL))
    {
        int n = GetLastError();
        CloseHandle(hf);
        VirtualFree(lpFileImage, 0, MEM_RELEASE);
        return FALSE;
    }

    //开始判断
    //转为PE的DOS头部
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpFileImage;
    //如果标记位不是"MZ"
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }
    pPeView->pFileBuffer = lpFileImage;
    pPeView->pDosHeader = pDos;
    //PE结构开始是DOS头部,DOS头部的e_lfanew位段的值是一个偏移
    //此偏移指明了新的EXE文件头开始的地址
    //从此位置解析为PE头部
    PIMAGE_NT_HEADERS64 pNT64 = (PIMAGE_NT_HEADERS64)((PCHAR)lpFileImage + pDos->e_lfanew);
    if (pNT64->Signature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)((PCHAR)pNT64 + 4);
    pPeView->pFileHeader = pFileHeader;
    pPeView->pOptionalHeader = &pNT64->OptionalHeader;

    // 判断是否为32位程序, 根据optioal header大小
    DWORD opSize = pFileHeader->SizeOfOptionalHeader;
    if (opSize == 0xe0) {
        bPE32 = TRUE;
    }
    else if (opSize != 0xf0) {
        return FALSE;
    }
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((PCHAR) pPeView->pOptionalHeader + opSize);
    pPeView->pSectionHeader = pSectionHeader;

    BOOL isPE = TRUE;
    CloseHandle(hf);
    return isPE;
}

// 文件头窗口处理函数
INT_PTR CALLBACK FileWndProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BOOL bRet = TRUE;
    switch (uMsg)
    {
    case WM_INITDIALOG:
    {
        TCHAR szBuffer[64] = { 0 };
        HWND ec = GetDlgItem(hDlg, IDC_MACHINE);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pFileHeader->Machine);
        SetWindowText(ec, szBuffer);

        ec = GetDlgItem(hDlg, IDC_NUMBEROFSECTIONS);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pFileHeader->NumberOfSections);
        SetWindowText(ec, szBuffer);

        ec = GetDlgItem(hDlg, IDC_TIMEDATESTAMP);
        wsprintf(szBuffer, TEXT("%08X"), pPeView->pFileHeader->TimeDateStamp);
        SetWindowText(ec, szBuffer);

        ec = GetDlgItem(hDlg, IDC_POINTERTOSYMBOLTABLE);
        wsprintf(szBuffer, TEXT("%08X"), pPeView->pFileHeader->PointerToSymbolTable);
        SetWindowText(ec, szBuffer);

        ec = GetDlgItem(hDlg, IDC_NUMBEROFSYMBOLS);
        wsprintf(szBuffer, TEXT("%08X"), pPeView->pFileHeader->NumberOfSymbols);
        SetWindowText(ec, szBuffer);

        ec = GetDlgItem(hDlg, IDC_SIZEOFOPTIONHEADER);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pFileHeader->SizeOfOptionalHeader);
        SetWindowText(ec, szBuffer);

        ec = GetDlgItem(hDlg, IDC_CHARACTERISTICS);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pFileHeader->Characteristics);
        SetWindowText(ec, szBuffer);
        break;
    }
    case WM_CLOSE:
        EndDialog(hDlg, 0);
        break;
    default:
        bRet = FALSE;
        break;
    }
    
    return bRet;
}

// 可选头窗口处理函数
INT_PTR CALLBACK OptionWndProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BOOL bRet = TRUE;
    switch (uMsg)
    {
    case WM_INITDIALOG:
    {   
        TCHAR szBuffer[64] = { 0 };
        if (bPE32) {
            PIMAGE_OPTIONAL_HEADER32 pOpHeader32 = &pPeView->pOptionalHeader->OptionalHeader32;
            HWND ec = GetDlgItem(hDlg, IDC_OPMAGIC);
            wsprintf(szBuffer, TEXT("%04X"), pOpHeader32->Magic);
            SetWindowText(ec, szBuffer);
        }
        else {
            PIMAGE_OPTIONAL_HEADER64 pOpHeader64 = &pPeView->pOptionalHeader->OptionalHeader64;
            HWND ec = GetDlgItem(hDlg, IDC_OPMAGIC);
            wsprintf(szBuffer, TEXT("%04X"), pOpHeader64->Magic);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_MAJORLINKERVERSION);
            wsprintf(szBuffer, TEXT("%02X"), pOpHeader64->MajorLinkerVersion);
            SetWindowText(ec, szBuffer);
        
            ec = GetDlgItem(hDlg, IDC_MINORLINKERVERSION);
            wsprintf(szBuffer, TEXT("%02X"), pOpHeader64->MinorLinkerVersion);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_SIZEOFCODE);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->SizeOfCode);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_SIZEOFINITDATA);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->SizeOfInitializedData);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_SIZEOFUNINITDATA);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->SizeOfUninitializedData);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_ENTRYPOINT);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->AddressOfEntryPoint);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_BASEOFCODE);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->BaseOfCode);
            SetWindowText(ec, szBuffer);

            /*ec = GetDlgItem(hDlg, IDC_BASEOFDATA);
            wsprintf(szBuffer, TEXT("%02X"), pOpHeader64->);
            SetWindowText(ec, szBuffer);*/

            ec = GetDlgItem(hDlg, IDC_IMAGEBASE);
            wsprintf(szBuffer, TEXT("%016I64X"), pOpHeader64->ImageBase);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_SECTIONALIGNMENT);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->SectionAlignment);
            SetWindowText(ec, szBuffer);
        
            ec = GetDlgItem(hDlg, IDC_FILEALIGNMENT);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->FileAlignment);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_MAJOROSVERSION);
            wsprintf(szBuffer, TEXT("%04X"), pOpHeader64->MajorOperatingSystemVersion);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_MINOROSVERSION);
            wsprintf(szBuffer, TEXT("%04X"), pOpHeader64->MinorOperatingSystemVersion);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_MAJORIMAGEVERSION);
            wsprintf(szBuffer, TEXT("%04X"), pOpHeader64->MajorImageVersion);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_MINORIMAGEVERSION);
            wsprintf(szBuffer, TEXT("%04X"), pOpHeader64->MinorImageVersion);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_MAJORSUBSYSTEMVERSION);
            wsprintf(szBuffer, TEXT("%04X"), pOpHeader64->MajorSubsystemVersion);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_MINORSUBSYSTEMVERSION);
            wsprintf(szBuffer, TEXT("%04X"), pOpHeader64->MinorSubsystemVersion);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_WIN32VERSIONVALUE);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->Win32VersionValue);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_SIZEOFIMAGE);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->SizeOfImage);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_SIZEOFHEADERS);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->SizeOfHeaders);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_CHECKSUM);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->CheckSum);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_SUBSYSTEM);
            wsprintf(szBuffer, TEXT("%04X"), pOpHeader64->Subsystem);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_DLLCHARACTERISTICS);
            wsprintf(szBuffer, TEXT("%04X"), pOpHeader64->DllCharacteristics);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_SIZEOFSTACKRESERVE);
            wsprintf(szBuffer, TEXT("%016I64X"), pOpHeader64->SizeOfStackReserve);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_SIZEOFSTACKCOMMIT);
            wsprintf(szBuffer, TEXT("%016I64X"), pOpHeader64->SizeOfStackCommit);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_SIZEOFHEAPCOMMIT);
            wsprintf(szBuffer, TEXT("%016I64X"), pOpHeader64->SizeOfHeapCommit);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_SIZEOFHEAPRESERVE);
            wsprintf(szBuffer, TEXT("%016I64X"), pOpHeader64->SizeOfHeapReserve);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_LOADERFLAGS);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->LoaderFlags);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_NUMBEROFRVAANDSIZES);
            wsprintf(szBuffer, TEXT("%08X"), pOpHeader64->NumberOfRvaAndSizes);
            SetWindowText(ec, szBuffer);
        }
        break; 
    }
    case WM_CLOSE:
        EndDialog(hDlg, 0);
        break;
    default:
        bRet = FALSE;
        break;
    }
    return bRet;
}

// 节表头窗口处理函数
INT_PTR CALLBACK SectionWndProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BOOL bRet = TRUE;
    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hDlg, 0);
        break;
    case WM_INITDIALOG:
    {
        HWND hListView = GetDlgItem(hDlg, IDC_LIST1);
        // 设置列标题
        LVCOLUMN lvc;
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;
        lvc.cx = 30;
        lvc.pszText = TEXT("#");
        ListView_InsertColumn(hListView, 0, &lvc);
        lvc.cx = 60;
        lvc.pszText = TEXT("Name");
        ListView_InsertColumn(hListView, 1, &lvc);
        lvc.cx = 80;
        lvc.pszText = TEXT("Virtual Size");
        ListView_InsertColumn(hListView, 2, &lvc);
        lvc.pszText = TEXT("Virtual Offset");
        ListView_InsertColumn(hListView, 3, &lvc);
        lvc.pszText = TEXT("Raw Size");
        ListView_InsertColumn(hListView, 4, &lvc);
        lvc.pszText = TEXT("Raw Offset");
        ListView_InsertColumn(hListView, 5, &lvc);
        lvc.cx = 100;
        lvc.pszText = TEXT("Characteristics");
        ListView_InsertColumn(hListView, 6, &lvc);

        // 遍历节表，输出信息
        PIMAGE_SECTION_HEADER pSectionHeader = pPeView->pSectionHeader;
        TCHAR szBuffer[64] = { 0 };
        for (int i = 0; i < pPeView->pFileHeader->NumberOfSections; i++, pSectionHeader++) {
            LVITEM lvItem;
            lvItem.mask = LVIF_TEXT;
            lvItem.iItem = i; // 第i行
            lvItem.pszText = szBuffer;
            
            wsprintf(szBuffer, TEXT("%d"), i+1); 
            lvItem.iSubItem = 0;
            ListView_InsertItem(hListView, &lvItem);

            memset(szBuffer, 0, 64);
            memcpy(szBuffer, pSectionHeader->Name, 8);
            wsprintf(szBuffer, TEXT("%s"), szBuffer);
            ListView_SetItemText(hListView, i, 1, szBuffer);

            wsprintf(szBuffer, TEXT("%08X"), pSectionHeader->Misc.VirtualSize);
            ListView_SetItemText(hListView, i, 2, szBuffer);

            wsprintf(szBuffer, TEXT("%08X"), pSectionHeader->VirtualAddress);
            ListView_SetItemText(hListView, i, 3, szBuffer);

            wsprintf(szBuffer, TEXT("%08X"), pSectionHeader->SizeOfRawData);
            ListView_SetItemText(hListView, i, 4, szBuffer);

            wsprintf(szBuffer, TEXT("%08X"), pSectionHeader->PointerToRawData);
            ListView_SetItemText(hListView, i, 5, szBuffer);

            wsprintf(szBuffer, TEXT("%08X"), pSectionHeader->Characteristics);
            ListView_SetItemText(hListView, i, 6, szBuffer);
        }
        break;
    }
    default:
        bRet = FALSE;
        break;
    }
    return bRet;
}


INT_PTR CALLBACK ImportWndProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BOOL bRet = TRUE;
    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hDlg, 0);
        break;
    case WM_INITDIALOG:
    {
        HWND hListView = GetDlgItem(hDlg, IDC_IMPORT_TABLE);
        LRESULT dwCurrentStyle = SendMessage(hListView, LVM_GETEXTENDEDLISTVIEWSTYLE, 0, 0);

        // 添加或移除指定的扩展风格
        LRESULT dwNewStyle = dwCurrentStyle | LVS_EX_FULLROWSELECT; // 添加全行选择风格

        SendMessage(hListView, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, dwNewStyle);
        // 设置列标题
        LVCOLUMN lvc;
        lvc.mask = LVCF_TEXT | LVCF_WIDTH;
        lvc.cx = 80;
        lvc.pszText = TEXT("Dll Name");
        ListView_InsertColumn(hListView, 0, &lvc);
        lvc.cx = 110;
        lvc.pszText = TEXT("Original First Thunk");
        ListView_InsertColumn(hListView, 1, &lvc);
        lvc.cx = 100;
        lvc.pszText = TEXT("Time/Date Stamp");
        ListView_InsertColumn(hListView, 2, &lvc);
        lvc.pszText = TEXT("Forwarder Chain");
        ListView_InsertColumn(hListView, 3, &lvc);
        lvc.cx = 80;
        lvc.pszText = TEXT("Name");
        ListView_InsertColumn(hListView, 4, &lvc);
        lvc.pszText = TEXT("First Thunk");
        ListView_InsertColumn(hListView, 5, &lvc);


        // 获取导入表的内存地址
        IMAGE_DATA_DIRECTORY dataDirectory = pPeView->pOptionalHeader->OptionalHeader64.DataDirectory[1];
        int i = 0;
        TCHAR szBuffer[64] = { 0 };
        PIMAGE_IMPORT_DESCRIPTOR pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((PCHAR)pPeView->pFileBuffer + RvaToFoa64(pPeView->pFileBuffer, dataDirectory.VirtualAddress));
        while(TRUE) {
            if (pImportDirectory->Characteristics == 0) {
                break;
            }
            LVITEM lvItem;
            lvItem.mask = LVIF_TEXT;
            lvItem.iItem = i; // 第i行
            lvItem.pszText = szBuffer;

            wsprintf(szBuffer, TEXT("%s"), (PCHAR)pPeView->pFileBuffer + RvaToFoa64(pPeView->pFileBuffer, pImportDirectory->Name));
            lvItem.iSubItem = 0;
            ListView_InsertItem(hListView, &lvItem);

            wsprintf(szBuffer, TEXT("%08X"), pImportDirectory->OriginalFirstThunk);
            ListView_SetItemText(hListView, i, 1, szBuffer);

            wsprintf(szBuffer, TEXT("%08X"), pImportDirectory->TimeDateStamp);
            ListView_SetItemText(hListView, i, 2, szBuffer);

            wsprintf(szBuffer, TEXT("%08X"), pImportDirectory->ForwarderChain);
            ListView_SetItemText(hListView, i, 3, szBuffer);

            wsprintf(szBuffer, TEXT("%08X"), pImportDirectory->Name);
            ListView_SetItemText(hListView, i, 4, szBuffer);

            wsprintf(szBuffer, TEXT("%08X"), pImportDirectory->FirstThunk);
            ListView_SetItemText(hListView, i, 5, szBuffer);
            
            i++;
            pImportDirectory++;

        }

        HWND hListView2 = GetDlgItem(hDlg, IDC_IMPORT_API_TABLE);
        // 设置列标题
        lvc.cx = 120;
        lvc.pszText = TEXT("API Name");
        ListView_InsertColumn(hListView2, 0, &lvc);
        lvc.cx = 100;
        lvc.pszText = TEXT("Thunk RVA");
        ListView_InsertColumn(hListView2, 1, &lvc);
        lvc.pszText = TEXT("Thunk Offset");
        ListView_InsertColumn(hListView2, 2, &lvc);
        lvc.pszText = TEXT("Thunk Value");
        ListView_InsertColumn(hListView2, 3, &lvc);
        lvc.pszText = TEXT("Hint");
        ListView_InsertColumn(hListView2, 4, &lvc);


        pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((PCHAR)pPeView->pFileBuffer + RvaToFoa64(pPeView->pFileBuffer, dataDirectory.VirtualAddress));
        PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)((PCHAR)pPeView->pFileBuffer + RvaToFoa64(pPeView->pFileBuffer, pImportDirectory->FirstThunk));
        PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
        i = 0;
        while (TRUE) {
            if (pThunkData->u1.Ordinal == 0) {
                break;
            }
            LVITEM lvItem;
            lvItem.mask = LVIF_TEXT;
            lvItem.iItem = i; // 第i行
            lvItem.pszText = szBuffer;

            if (pThunkData->u1.Ordinal < IMAGE_ORDINAL_FLAG) {
                pImportByName = (PIMAGE_IMPORT_BY_NAME)((PCHAR)pPeView->pFileBuffer + RvaToFoa64(pPeView->pFileBuffer, pThunkData->u1.AddressOfData));
                wsprintf(szBuffer, TEXT("%s"), pImportByName->Name);
                lvItem.iSubItem = 0;
                ListView_InsertItem(hListView2, &lvItem);

                size_t offset = (PCHAR)pThunkData - (PCHAR)pPeView->pFileBuffer;
                wsprintf(szBuffer, TEXT("%08I64X"), FoaToRva64(pPeView->pFileBuffer, offset));
                ListView_SetItemText(hListView2, i, 1, szBuffer);

                wsprintf(szBuffer, TEXT("%08I64X"), offset);
                ListView_SetItemText(hListView2, i, 2, szBuffer);

                wsprintf(szBuffer, TEXT("%08I64X"), pThunkData->u1.AddressOfData);
                ListView_SetItemText(hListView2, i, 3, szBuffer);

                wsprintf(szBuffer, TEXT("%04X"), pImportByName->Hint);
                ListView_SetItemText(hListView2, i, 4, szBuffer);
            }
            pThunkData++;
            i++;

        }
        break;
    }
    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_IMPORT_TABLE:
        {
            switch (HIWORD(wParam))
            {
            default:
                bRet = FALSE;
                break;
            }
        }

        default:
            bRet = FALSE;
            break;
        }
        
    }
    case WM_NOTIFY:
    {
        NMHDR* pHdr = (NMHDR*)lParam;
        HWND hListView = GetDlgItem(hDlg, IDC_IMPORT_TABLE);
        if (pHdr->hwndFrom == hListView && pHdr->code == LVN_ITEMCHANGED)
        {
            NMLISTVIEW* pListViewNotify = (NMLISTVIEW*)lParam;
            if ((pListViewNotify->uChanged & LVIF_STATE) &&
                ((pListViewNotify->uOldState ^ pListViewNotify->uNewState) & LVIS_SELECTED))
            {
                // 选中状态发生了变化
                int changedItemIndex = pListViewNotify->iItem;
                // 在这里处理选中项变化的逻辑
                HWND hListView2 = GetDlgItem(hDlg, IDC_IMPORT_API_TABLE);
                ListView_DeleteAllItems(hListView2);
                IMAGE_DATA_DIRECTORY dataDirectory = pPeView->pOptionalHeader->OptionalHeader64.DataDirectory[1];
                PIMAGE_IMPORT_DESCRIPTOR pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((PCHAR)pPeView->pFileBuffer + RvaToFoa64(pPeView->pFileBuffer, dataDirectory.VirtualAddress));
                pImportDirectory += changedItemIndex;
                PIMAGE_THUNK_DATA pThunkData = (PIMAGE_THUNK_DATA)((PCHAR)pPeView->pFileBuffer + RvaToFoa64(pPeView->pFileBuffer, pImportDirectory->FirstThunk));
                PIMAGE_IMPORT_BY_NAME pImportByName = NULL;

                int i = 0;
                TCHAR szBuffer[64] = { 0 };
                while (TRUE) {
                    if (pThunkData->u1.Ordinal == 0) {
                        break;
                    }
                    LVITEM lvItem;
                    lvItem.mask = LVIF_TEXT;
                    lvItem.iItem = i; // 第i行
                    lvItem.pszText = szBuffer;

                    if (pThunkData->u1.Ordinal < IMAGE_ORDINAL_FLAG) {
                        pImportByName = (PIMAGE_IMPORT_BY_NAME)((PCHAR)pPeView->pFileBuffer + RvaToFoa64(pPeView->pFileBuffer, pThunkData->u1.AddressOfData));
                        wsprintf(szBuffer, TEXT("%s"), pImportByName->Name);
                        lvItem.iSubItem = 0;
                        ListView_InsertItem(hListView2, &lvItem);

                        size_t offset = (PCHAR)pThunkData - (PCHAR)pPeView->pFileBuffer;
                        wsprintf(szBuffer, TEXT("%08I64X"), FoaToRva64(pPeView->pFileBuffer, offset));
                        ListView_SetItemText(hListView2, i, 1, szBuffer);

                        wsprintf(szBuffer, TEXT("%08I64X"), offset);
                        ListView_SetItemText(hListView2, i, 2, szBuffer);

                        wsprintf(szBuffer, TEXT("%08I64X"), pThunkData->u1.AddressOfData);
                        ListView_SetItemText(hListView2, i, 3, szBuffer);

                        wsprintf(szBuffer, TEXT("%04X"), pImportByName->Hint);
                        ListView_SetItemText(hListView2, i, 4, szBuffer);
                    }
                    pThunkData++;
                    i++;

                }
            }
        }
        break;
    }
    default:
        bRet = FALSE;
        break;
    }
    return bRet;
}

INT_PTR CALLBACK DirecWndProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BOOL bRet = TRUE;
    switch (uMsg)
    {
    case WM_CLOSE:
        EndDialog(hDlg, 0);
        break;
    case WM_INITDIALOG:
    {
        IMAGE_DATA_DIRECTORY dataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = { 0 };
        if (bPE32) {
            memcpy(dataDirectory, pPeView->pOptionalHeader->OptionalHeader32.DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES*sizeof(IMAGE_DATA_DIRECTORY));
        }
        else {
            memcpy(dataDirectory, pPeView->pOptionalHeader->OptionalHeader64.DataDirectory, IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY));

        }
        TCHAR szBuffer[64] = { 0 };
        for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
            HWND ec = GetDlgItem(hDlg, IDC_DIREC_RVA1 + i);
            wsprintf(szBuffer, TEXT("%08X"), dataDirectory[i].VirtualAddress);
            SetWindowText(ec, szBuffer);

            ec = GetDlgItem(hDlg, IDC_DIREC_SIZE1 + i);
            wsprintf(szBuffer, TEXT("%08X"), dataDirectory[i].Size);
            SetWindowText(ec, szBuffer);
        }
        break;
    }
    case WM_COMMAND:
    {
        switch (LOWORD(wParam))
        {
        case IDC_IMPORT_DIREC:
        {
            DialogBox(hIns, MAKEINTRESOURCE(IDD_IMPORT_DIREC), hDlg, ImportWndProc);
            break;
        }
        default:
            bRet = FALSE;
            break;
        }
    }
    default:
        bRet = FALSE;
        break;
    }
    return bRet;
}

INT_PTR CALLBACK DosWndProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    BOOL bRet = TRUE;
    switch (uMsg)
    {
    case WM_INITDIALOG:
    {
        TCHAR szBuffer[64];
        HWND ecMagic = GetDlgItem(hDlg, IDC_MAGIC);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_magic);
        SetWindowText(ecMagic, szBuffer);
        HWND ecCblp = GetDlgItem(hDlg, IDC_CBLP);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_cblp);
        SetWindowText(ecCblp, szBuffer);
        HWND ecCp = GetDlgItem(hDlg, IDC_CP);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_cp);
        SetWindowText(ecCp, szBuffer);
        HWND ecCrlc = GetDlgItem(hDlg, IDC_CRLC);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_crlc);
        SetWindowText(ecCrlc, szBuffer);
        HWND ec = GetDlgItem(hDlg, IDC_CPARHDR);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_cparhdr);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_MINALLOC);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_minalloc);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_MAXALLOC);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_maxalloc);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_SS);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_ss);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_SP);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_sp);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_CSUM);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_csum);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_IP);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_ip);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_CS);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_cs);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_LFARLC);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_lfarlc);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_OVNO);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_ovno);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_OEMID);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_oemid);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_OEMINFO);
        wsprintf(szBuffer, TEXT("%04X"), pPeView->pDosHeader->e_oeminfo);
        SetWindowText(ec, szBuffer);
        ec = GetDlgItem(hDlg, IDC_LFANEW);
        wsprintf(szBuffer, TEXT("%08X"), pPeView->pDosHeader->e_lfanew);
        SetWindowText(ec, szBuffer);
        break;
    }
    case WM_COMMAND:
    {
        switch (LOWORD(wParam)) {
        case IDC_FILE_HEADER:
        {
            DialogBox(hIns, MAKEINTRESOURCE(IDD_FILE_HEADER), hDlg, FileWndProc);
            break;
        }
        case IDC_OPTION_HEADER:
        {
            DialogBox(hIns, MAKEINTRESOURCE(IDD_OPTION_HEADER), hDlg, OptionWndProc);
            break;
        }
        case IDC_SEC_HEADER:
        {
            DialogBox(hIns, MAKEINTRESOURCE(IDD_SECTION_HEADER), hDlg, SectionWndProc);
            break;
        }
        case IDC_DIREC:
        {
            DialogBox(hIns, MAKEINTRESOURCE(IDD_DIRECTORY), hDlg, DirecWndProc);
            break;
        }
        case IDC_SAVE:
        {   
            //修改DOS头
            PIMAGE_DOS_HEADER pDos = pPeView->pDosHeader;
            EditDosHeader(hDlg, pDos);

            //保存文件
            PIMAGE_FILE_HEADER pFil = pPeView->pFileHeader;
            PIMAGE_SECTION_HEADER pSec = pPeView->pSectionHeader;
            DWORD dwCurSize = pSec[pFil->NumberOfSections - 1].SizeOfRawData + pSec[pFil->NumberOfSections - 1].PointerToRawData;

            if (!WritePEFile(pPeView->pFileBuffer, dwCurSize, filePath)) {
                TCHAR szBuffer[1024] = { 0 };
                wsprintf(szBuffer, TEXT("文件成功保存至: %s"), filePath);
                MessageBox(hDlg, szBuffer, TEXT("Info"), MB_OK);
            }
            
            break;
        }
        }
        break;
    }
    case WM_CLOSE:
        EndDialog(hDlg, 0);
        break;
    default:
        bRet = FALSE;
        break;
    }
    return bRet;
}

// 主对话框
INT_PTR CALLBACK MainDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	BOOL bRet = TRUE;
	
	switch (uMsg)
	{
	case WM_INITDIALOG:
    {
        HMENU hMenu = LoadMenu(GetModuleHandle(NULL), MAKEINTRESOURCE(IDR_MENU1));
        SetMenu(hDlg, hMenu);
        break; 
    }
    case WM_COMMAND:
    {
        int wmId = LOWORD(wParam);
        // 分析菜单选择:
        switch (wmId)
        {
        case ID_ABOUT:
            MessageBox(hDlg, TEXT("PE Editor"), TEXT("About"), MB_OK);
            break;
        case ID_EXIT:
            DestroyWindow(hDlg);
            break;
        case ID_OPEN:
        {
            HANDLE hf = OnOpen(hDlg, wParam, lParam);
            
            if (IsPEFile(&peView, hf)) {
                DialogBox(hIns, MAKEINTRESOURCE(IDD_DOS_HEADER), hDlg, DosWndProc);
            }
            else {
                CloseHandle(hf);
                MessageBox(hDlg, TEXT("不是PE文件"), TEXT("Info"), MB_OK);
            }
            break;
        }
        default:
            bRet = FALSE;
            break;
        }
    }
    break;
	case WM_CLOSE:
		EndDialog(hDlg, 0);
		break;
	default:
		bRet = FALSE;
		break;
	}
	return bRet;
}


int APIENTRY WinMain(HINSTANCE hIns, HINSTANCE hPrevIns, LPTSTR lpCmdLine, int nShowCmd) {
    if (!AllocConsole()) {
        DWORD error = GetLastError();
        // 输出错误代码到调试器或日志
        fprintf(stderr, "Failed to create console. Error code: %lu\n", error);
    }
    else {
        g_hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        TCHAR szBuffer[1024] = TEXT("Console created successfully.\n");
        WriteConsole(g_hOutput, szBuffer, strlen(szBuffer), NULL, NULL); // 应该能看到这条消息
    }
    DialogBox(hIns, MAKEINTRESOURCE(IDD_MAIN), NULL, MainDlgProc);
	return 0;
}
#include <Windows.h>
#include <stdio.h>
#include "resource.h"

DWORD Align(IN DWORD dwAlign, IN DWORD dwVar)
{
    //小于等于对齐直接返回当前对齐
    if (dwVar <= dwAlign)
    {
        return dwAlign;
    }
    //如果可以整除处理
    if (dwVar % dwAlign == 0)
    {
        return dwVar;
    }
    //大于对齐且不能被整除处理
    return dwAlign * (dwVar / dwAlign + 1);
}

size_t RvaToFoa64(LPVOID pBuffer, size_t dwRva)
{
    //定位PE结构
    PIMAGE_DOS_HEADER			pDos = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS64			pNth = (PIMAGE_NT_HEADERS64)((PCHAR)pBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER			pFil = (PIMAGE_FILE_HEADER)((PCHAR)pNth + 4);
    PIMAGE_OPTIONAL_HEADER64	pOpo = (PIMAGE_OPTIONAL_HEADER64)((PCHAR)pFil + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER		pSec = (PIMAGE_SECTION_HEADER)((PCHAR)pOpo + pFil->SizeOfOptionalHeader);

    //转换地址是否在头+节表中
    if (dwRva < pOpo->SizeOfHeaders)
    {
        return dwRva;
    }

    //遍历转换地址在哪个节中
    for (size_t i = 0; i < pFil->NumberOfSections; i++)
    {
        if ((dwRva >= pSec[i].VirtualAddress) && (dwRva < pSec[i].VirtualAddress + pSec[i].Misc.VirtualSize))
        {
            return dwRva - pSec[i].VirtualAddress + pSec[i].PointerToRawData;
        }

    }

    return 0;
}

size_t FoaToRva64(LPVOID pFileBuffer, size_t FOA)
{
    int i = 0;//用于遍历节表。
    //	size_t RVA = 0;

        //定义表头指针
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS64 pNtHeader = NULL;
    PIMAGE_FILE_HEADER pFileHeader = NULL;
    PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

    //给表头赋初值
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNtHeader = (PIMAGE_NT_HEADERS64)((PCHAR)pDosHeader + pDosHeader->e_lfanew);
    pFileHeader = (PIMAGE_FILE_HEADER)((PCHAR)pNtHeader + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((PCHAR)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
    //第一个节表头
    pSectionHeader = (PIMAGE_SECTION_HEADER)((PCHAR)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

    if (FOA < pSectionHeader->PointerToRawData)//判断是否位于 头区
        return FOA; //这是RVA == FOA ;

    for (i = 0; i < pFileHeader->NumberOfSections; i++)//循环遍历节表头
    {
        if (i)//遍历节表头，第一次不遍历，
            pSectionHeader = (PIMAGE_SECTION_HEADER)((PCHAR)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);

        if (FOA >= pSectionHeader->PointerToRawData)//是否大于这个节表的FOA
        {
            if (FOA < pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData)//判断是否在这个节表区域
                return (FOA - pSectionHeader->PointerToRawData) + pSectionHeader->VirtualAddress;//计算并返回RVA
        }
    }

    return 0;
}

int WritePEFile(PVOID pFileAddress, DWORD FileSize, LPSTR FilePath)
{
    int ret = 0;

    FILE* pf = fopen(FilePath, "wb");
    if (pf == NULL)
    {
        ret = -5;
        printf("func fopen() error :%d!\n", ret);
        return ret;
    }

    fwrite(pFileAddress, FileSize, 1, pf);

    fclose(pf);

    return ret;
}

BOOL MoveNtAndSectionToDosStub(IN PCHAR pBuffer)
{
    //定位结构
    PIMAGE_DOS_HEADER        pDos = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS        pNth = (PIMAGE_NT_HEADERS)(pBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER		 pFil = (PIMAGE_FILE_HEADER)((PUCHAR)pNth + 4);
    PIMAGE_OPTIONAL_HEADER   pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFil + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER    pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo + pFil->SizeOfOptionalHeader);

    //清空DOS_STUB数据
    memset(pBuffer + sizeof(IMAGE_DOS_HEADER), 0, pDos->e_lfanew - sizeof(IMAGE_DOS_HEADER));

    //移动数据大小
    DWORD dwMoveSize = sizeof(IMAGE_NT_HEADERS) + pFil->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;

    //备份数据
    PUCHAR pTemp = (PUCHAR)malloc(dwMoveSize);
    if (!pTemp)
    {
        return FALSE;
    }
    memset(pTemp, 0, dwMoveSize);
    memcpy(pTemp, pBuffer + pDos->e_lfanew, dwMoveSize);

    //清空默认数据
    memset(pBuffer + pDos->e_lfanew, 0, dwMoveSize);

    //移动数据
    memcpy(pBuffer + sizeof(IMAGE_DOS_HEADER), pTemp, dwMoveSize);

    //修正e_lfanew指向
    pDos->e_lfanew = sizeof(IMAGE_DOS_HEADER);

    free(pTemp);

    return TRUE;
}

PVOID AddNewSection(PCHAR pBuffer, DWORD dwSectionSize, LPDWORD pNewFileSize)
{
    //定位结构
    PIMAGE_DOS_HEADER        pDos = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS        pNth = (PIMAGE_NT_HEADERS)(pBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER		 pFil = (PIMAGE_FILE_HEADER)((PUCHAR)pNth + 4);
    PIMAGE_OPTIONAL_HEADER   pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFil + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER    pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo + pFil->SizeOfOptionalHeader);

    //判断头部是否有空间新增节
    if (pBuffer + pOpo->SizeOfHeaders - &pSec[pFil->NumberOfSections + 1] < IMAGE_SIZEOF_SECTION_HEADER)
    {
        //抹除DOS_STUB数据并将NT,SECTION整理向上移动
        BOOL bRet = MoveNtAndSectionToDosStub(pBuffer);
        if (!bRet)
        {
            printf("AddNewSection MoveNtAndSectionToDosStub Fail \r\n");
            free(pBuffer);
            return NULL;
        }

        pDos = (PIMAGE_DOS_HEADER)pBuffer;
        pNth = (PIMAGE_NT_HEADERS)(pBuffer + pDos->e_lfanew);
        pFil = (PIMAGE_FILE_HEADER)((PUCHAR)pNth + 4);
        pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFil + IMAGE_SIZEOF_FILE_HEADER);
        pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo + pFil->SizeOfOptionalHeader);

    }

    //填充新增节数据
    CHAR szName[] = ".Kernel";
    memcpy(pSec[pFil->NumberOfSections].Name, szName, 8);
    pSec[pFil->NumberOfSections].Misc.VirtualSize = dwSectionSize;//内存中对齐前的大小
    pSec[pFil->NumberOfSections].VirtualAddress = Align(pOpo->SectionAlignment, pSec[pFil->NumberOfSections - 1].Misc.VirtualSize + pSec[pFil->NumberOfSections - 1].VirtualAddress);//内存中的偏移
    pSec[pFil->NumberOfSections].SizeOfRawData = Align(pOpo->FileAlignment, dwSectionSize);//文件中对齐后的大小
    pSec[pFil->NumberOfSections].PointerToRawData = Align(pOpo->FileAlignment, pSec[pFil->NumberOfSections - 1].PointerToRawData + pSec[pFil->NumberOfSections - 1].SizeOfRawData);//文件中的偏移
    pSec[pFil->NumberOfSections].PointerToRelocations = 0;
    pSec[pFil->NumberOfSections].PointerToLinenumbers = 0;
    pSec[pFil->NumberOfSections].NumberOfRelocations = 0;
    pSec[pFil->NumberOfSections].NumberOfLinenumbers = 0;
    pSec[pFil->NumberOfSections].Characteristics |= pSec->Characteristics;//默认代码节
    pSec[pFil->NumberOfSections].Characteristics |= 0xC0000040;

    //新增节后补充大小为IMAGE_SECTION_HEADER结构的0数据
    memset(&pSec[pFil->NumberOfSections + 1], 0, IMAGE_SIZEOF_SECTION_HEADER);

    //修复默认节数量
    pFil->NumberOfSections++;

    //修复内存镜像大小
    pOpo->SizeOfImage += Align(pOpo->SectionAlignment, dwSectionSize);

    //默认文件大小
    DWORD dwOldSize = pSec[pFil->NumberOfSections - 2].SizeOfRawData + pSec[pFil->NumberOfSections - 2].PointerToRawData;

    //当前文件大小
    DWORD dwNewSize = pSec[pFil->NumberOfSections - 1].SizeOfRawData + pSec[pFil->NumberOfSections - 1].PointerToRawData;
    if (pNewFileSize)
    {
        *pNewFileSize = dwNewSize;
    }

    //重新分配缓冲区
    PUCHAR pTemp = (PUCHAR)malloc(dwNewSize);
    if (!pTemp)
    {
        printf("AddNewSection malloc Fail \r\n");
        free(pBuffer);
        return NULL;
    }
    memset(pTemp, 0, dwNewSize);
    memcpy(pTemp, pBuffer, dwOldSize);
    free(pBuffer);

    return pTemp;
}

//修改DOS头
BOOL EditDosHeader(HWND hDlg, PIMAGE_DOS_HEADER pDosHeader) {
    int bufferSize;
    TCHAR szBuffer[64];
    HWND ec;
    char* endptr;

    ec = GetDlgItem(hDlg, IDC_MAGIC);
    bufferSize = GetWindowTextLength(ec) + 1; 
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_magic = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_CBLP);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_cblp = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_CP);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_cp = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_CRLC);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_crlc = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_CPARHDR);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_cparhdr = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_MINALLOC);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_minalloc = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_MAXALLOC);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_maxalloc = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_SS);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_ss = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_SP);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_sp = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_CSUM);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_csum = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_IP);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_ip = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_CS);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_cs = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_LFARLC);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_lfarlc = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_OVNO);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_ovno = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_OEMID);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_oemid = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_OEMINFO);
    bufferSize = GetWindowTextLengthA(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_oeminfo = strtol(szBuffer, &endptr, 16);

    ec = GetDlgItem(hDlg, IDC_LFANEW);
    bufferSize = GetWindowTextLength(ec) + 1;
    GetWindowText(ec, szBuffer, bufferSize);
    pDosHeader->e_lfanew = strtol(szBuffer, &endptr, 16);

    return TRUE;
}
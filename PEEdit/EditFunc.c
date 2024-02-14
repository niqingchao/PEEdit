#include <Windows.h>
#include <stdio.h>
#include "resource.h"

DWORD Align(IN DWORD dwAlign, IN DWORD dwVar)
{
    //С�ڵ��ڶ���ֱ�ӷ��ص�ǰ����
    if (dwVar <= dwAlign)
    {
        return dwAlign;
    }
    //���������������
    if (dwVar % dwAlign == 0)
    {
        return dwVar;
    }
    //���ڶ����Ҳ��ܱ���������
    return dwAlign * (dwVar / dwAlign + 1);
}

size_t RvaToFoa64(LPVOID pBuffer, size_t dwRva)
{
    //��λPE�ṹ
    PIMAGE_DOS_HEADER			pDos = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS64			pNth = (PIMAGE_NT_HEADERS64)((PCHAR)pBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER			pFil = (PIMAGE_FILE_HEADER)((PCHAR)pNth + 4);
    PIMAGE_OPTIONAL_HEADER64	pOpo = (PIMAGE_OPTIONAL_HEADER64)((PCHAR)pFil + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER		pSec = (PIMAGE_SECTION_HEADER)((PCHAR)pOpo + pFil->SizeOfOptionalHeader);

    //ת����ַ�Ƿ���ͷ+�ڱ���
    if (dwRva < pOpo->SizeOfHeaders)
    {
        return dwRva;
    }

    //����ת����ַ���ĸ�����
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
    int i = 0;//���ڱ����ڱ�
    //	size_t RVA = 0;

        //�����ͷָ��
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS64 pNtHeader = NULL;
    PIMAGE_FILE_HEADER pFileHeader = NULL;
    PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

    //����ͷ����ֵ
    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    pNtHeader = (PIMAGE_NT_HEADERS64)((PCHAR)pDosHeader + pDosHeader->e_lfanew);
    pFileHeader = (PIMAGE_FILE_HEADER)((PCHAR)pNtHeader + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER)((PCHAR)pFileHeader + IMAGE_SIZEOF_FILE_HEADER);
    //��һ���ڱ�ͷ
    pSectionHeader = (PIMAGE_SECTION_HEADER)((PCHAR)pOptionHeader + pFileHeader->SizeOfOptionalHeader);

    if (FOA < pSectionHeader->PointerToRawData)//�ж��Ƿ�λ�� ͷ��
        return FOA; //����RVA == FOA ;

    for (i = 0; i < pFileHeader->NumberOfSections; i++)//ѭ�������ڱ�ͷ
    {
        if (i)//�����ڱ�ͷ����һ�β�������
            pSectionHeader = (PIMAGE_SECTION_HEADER)((PCHAR)pSectionHeader + IMAGE_SIZEOF_SECTION_HEADER);

        if (FOA >= pSectionHeader->PointerToRawData)//�Ƿ��������ڱ��FOA
        {
            if (FOA < pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData)//�ж��Ƿ�������ڱ�����
                return (FOA - pSectionHeader->PointerToRawData) + pSectionHeader->VirtualAddress;//���㲢����RVA
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
    //��λ�ṹ
    PIMAGE_DOS_HEADER        pDos = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS        pNth = (PIMAGE_NT_HEADERS)(pBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER		 pFil = (PIMAGE_FILE_HEADER)((PUCHAR)pNth + 4);
    PIMAGE_OPTIONAL_HEADER   pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFil + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER    pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo + pFil->SizeOfOptionalHeader);

    //���DOS_STUB����
    memset(pBuffer + sizeof(IMAGE_DOS_HEADER), 0, pDos->e_lfanew - sizeof(IMAGE_DOS_HEADER));

    //�ƶ����ݴ�С
    DWORD dwMoveSize = sizeof(IMAGE_NT_HEADERS) + pFil->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;

    //��������
    PUCHAR pTemp = (PUCHAR)malloc(dwMoveSize);
    if (!pTemp)
    {
        return FALSE;
    }
    memset(pTemp, 0, dwMoveSize);
    memcpy(pTemp, pBuffer + pDos->e_lfanew, dwMoveSize);

    //���Ĭ������
    memset(pBuffer + pDos->e_lfanew, 0, dwMoveSize);

    //�ƶ�����
    memcpy(pBuffer + sizeof(IMAGE_DOS_HEADER), pTemp, dwMoveSize);

    //����e_lfanewָ��
    pDos->e_lfanew = sizeof(IMAGE_DOS_HEADER);

    free(pTemp);

    return TRUE;
}

PVOID AddNewSection(PCHAR pBuffer, DWORD dwSectionSize, LPDWORD pNewFileSize)
{
    //��λ�ṹ
    PIMAGE_DOS_HEADER        pDos = (PIMAGE_DOS_HEADER)pBuffer;
    PIMAGE_NT_HEADERS        pNth = (PIMAGE_NT_HEADERS)(pBuffer + pDos->e_lfanew);
    PIMAGE_FILE_HEADER		 pFil = (PIMAGE_FILE_HEADER)((PUCHAR)pNth + 4);
    PIMAGE_OPTIONAL_HEADER   pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFil + IMAGE_SIZEOF_FILE_HEADER);
    PIMAGE_SECTION_HEADER    pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo + pFil->SizeOfOptionalHeader);

    //�ж�ͷ���Ƿ��пռ�������
    if (pBuffer + pOpo->SizeOfHeaders - &pSec[pFil->NumberOfSections + 1] < IMAGE_SIZEOF_SECTION_HEADER)
    {
        //Ĩ��DOS_STUB���ݲ���NT,SECTION���������ƶ�
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

    //�������������
    CHAR szName[] = ".Kernel";
    memcpy(pSec[pFil->NumberOfSections].Name, szName, 8);
    pSec[pFil->NumberOfSections].Misc.VirtualSize = dwSectionSize;//�ڴ��ж���ǰ�Ĵ�С
    pSec[pFil->NumberOfSections].VirtualAddress = Align(pOpo->SectionAlignment, pSec[pFil->NumberOfSections - 1].Misc.VirtualSize + pSec[pFil->NumberOfSections - 1].VirtualAddress);//�ڴ��е�ƫ��
    pSec[pFil->NumberOfSections].SizeOfRawData = Align(pOpo->FileAlignment, dwSectionSize);//�ļ��ж����Ĵ�С
    pSec[pFil->NumberOfSections].PointerToRawData = Align(pOpo->FileAlignment, pSec[pFil->NumberOfSections - 1].PointerToRawData + pSec[pFil->NumberOfSections - 1].SizeOfRawData);//�ļ��е�ƫ��
    pSec[pFil->NumberOfSections].PointerToRelocations = 0;
    pSec[pFil->NumberOfSections].PointerToLinenumbers = 0;
    pSec[pFil->NumberOfSections].NumberOfRelocations = 0;
    pSec[pFil->NumberOfSections].NumberOfLinenumbers = 0;
    pSec[pFil->NumberOfSections].Characteristics |= pSec->Characteristics;//Ĭ�ϴ����
    pSec[pFil->NumberOfSections].Characteristics |= 0xC0000040;

    //�����ں󲹳��СΪIMAGE_SECTION_HEADER�ṹ��0����
    memset(&pSec[pFil->NumberOfSections + 1], 0, IMAGE_SIZEOF_SECTION_HEADER);

    //�޸�Ĭ�Ͻ�����
    pFil->NumberOfSections++;

    //�޸��ڴ澵���С
    pOpo->SizeOfImage += Align(pOpo->SectionAlignment, dwSectionSize);

    //Ĭ���ļ���С
    DWORD dwOldSize = pSec[pFil->NumberOfSections - 2].SizeOfRawData + pSec[pFil->NumberOfSections - 2].PointerToRawData;

    //��ǰ�ļ���С
    DWORD dwNewSize = pSec[pFil->NumberOfSections - 1].SizeOfRawData + pSec[pFil->NumberOfSections - 1].PointerToRawData;
    if (pNewFileSize)
    {
        *pNewFileSize = dwNewSize;
    }

    //���·��仺����
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

//�޸�DOSͷ
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
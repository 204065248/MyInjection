#include "GetProcAddressR.h"

// ����ʵ����һ����С�� GetProcAddress �Ա���ʹ�ñ��� kernel32!GetProcAddress
// ���޷�����������صĿ��еĵ�����ַ��
FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName) {
	FARPROC fpResult = NULL;

	if (hModule == NULL)
		return NULL;

	// ģ����
	UINT_PTR uiLibraryAddress = (UINT_PTR)hModule;

	try {
		// ��ȡģ�� NT Header �� VA
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

		PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		// ��ȡ����Ŀ¼�� VA
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

		// ��ȡ��ַ����� VA
		UINT_PTR uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

		// ��ȡ����ָ������� VA
		UINT_PTR uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

		// ��ȡ������������� VA
		UINT_PTR uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

		// ���������ǰ����ƻ��ǰ���ŵ���...
		if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000) {
			// ����ŵ���

			// ʹ�� import ordinal (- export ordinal base) ��Ϊ��ַ���������
			uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));

			// ����������뺯���ĵ�ַ
			fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
		} else {
			// �����Ƶ���
			DWORD dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--) {
				char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));

				// ���������Ƿ���ƥ��...
				if (strcmp(cpExportedFunctionName, lpProcName) == 0) {
					// ʹ�ú�������������Ϊ����ָ�����������
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// ���㺯���������ַ
					fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));

					break;
				}

				// ��ȡ��һ�������ĺ�����
				uiNameArray += sizeof(DWORD);

				// ��ȡ��һ�������ĺ���������
				uiNameOrdinals += sizeof(WORD);
			}
		}
	} catch (...) {
		fpResult = NULL;
	}

	return fpResult;
}
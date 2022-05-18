#include "GetProcAddressR.h"

// 我们实现了一个最小的 GetProcAddress 以避免使用本机 kernel32!GetProcAddress
// 将无法解析反射加载的库中的导出地址。
FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName) {
	FARPROC fpResult = NULL;

	if (hModule == NULL)
		return NULL;

	// 模块句柄
	UINT_PTR uiLibraryAddress = (UINT_PTR)hModule;

	try {
		// 获取模块 NT Header 的 VA
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

		PIMAGE_DATA_DIRECTORY pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		// 获取导出目录的 VA
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

		// 获取地址数组的 VA
		UINT_PTR uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

		// 获取名称指针数组的 VA
		UINT_PTR uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

		// 获取名称序数数组的 VA
		UINT_PTR uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

		// 测试我们是按名称还是按序号导入...
		if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000) {
			// 按序号导入

			// 使用 import ordinal (- export ordinal base) 作为地址数组的索引
			uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));

			// 解析这个导入函数的地址
			fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
		} else {
			// 按名称导入
			DWORD dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--) {
				char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));

				// 测试我们是否有匹配...
				if (strcmp(cpExportedFunctionName, lpProcName) == 0) {
					// 使用函数名称序数作为名称指针数组的索引
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

					// 计算函数的虚拟地址
					fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));

					break;
				}

				// 获取下一个导出的函数名
				uiNameArray += sizeof(DWORD);

				// 获取下一个导出的函数名序数
				uiNameOrdinals += sizeof(WORD);
			}
		}
	} catch (...) {
		fpResult = NULL;
	}

	return fpResult;
}
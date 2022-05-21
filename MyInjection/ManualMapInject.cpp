
#include "pch.h"
#include "framework.h"
#include "ManualMapInject.h"


#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif
#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif



CManualMapInject::CManualMapInject() {
}

CManualMapInject::~CManualMapInject() {
}

bool CManualMapInject::InjectorDLL(LPBYTE lpDllBuff, DWORD dwFileSize, HANDLE hProc) {
	// 检测
	if (!hProc || !IsCorrectTargetArchitecture(hProc)) {
		return false;
	}

	if (ManualMapDll(hProc, lpDllBuff, dwFileSize)) {
		return true;
	}

	return false;
}

bool CManualMapInject::IsCorrectTargetArchitecture(HANDLE hProc) {
	// 获取自身进程位数
	HANDLE hCurrentProc = GetCurrentProcess();
	BOOL isCurrentWow64 = FALSE;
	IsWow64Process(hCurrentProc, &isCurrentWow64);

	// 获取目标进程位数
	BOOL isTargetWow64 = FALSE;
	IsWow64Process(hProc, &isTargetWow64);

	return isCurrentWow64 == isTargetWow64;
}

// 写入节表
bool WriteSections(HANDLE hProc, LPBYTE lpDllBuff, LPBYTE pTargetBase, IMAGE_SECTION_HEADER* pSectionHeader, IMAGE_FILE_HEADER* pOldFileHeader) {
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, lpDllBuff + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
				return false;
			}
		}
	}
	return true;
}

// 获取返回模块句柄
HINSTANCE GetReturnModule(HANDLE hProc, LPBYTE lpParamBuff) {
	HINSTANCE hModule = NULL;
	while (!hModule) {
		// 判断进程是否照常运行
		DWORD dwExitCode = 0;
		GetExitCodeProcess(hProc, &dwExitCode);
		if (dwExitCode != STILL_ACTIVE) {
			return false;
		}

		// 读取返回参数，由于GetExitCodeThread只能返回DWORD参数
		// 如果是64位返回QWORD类型会丢失内容
		// 所以这里使用之前的结构体来获取返回值
		MANUAL_MAPPING_DATA returnData{ 0 };
		ReadProcessMemory(hProc, lpParamBuff, &returnData, sizeof(returnData), nullptr);
		hModule = returnData.hMod;
		Sleep(1);
	}
	return hModule;
}

bool ManualMapDll(HANDLE hProc, BYTE* lpDllBuff, SIZE_T nFileSize, bool bClearHeader,
	bool bClearNonNeededSections, bool bAdjustProtections, bool bSEHExceptionSupport,
	DWORD fdwReason, LPVOID lpReserved) {

	bool isSuccess = false;

	LPBYTE lpTargetBase = nullptr;
	LPBYTE lpParamBuff = nullptr;
	LPVOID lpShellcode = nullptr;
	LPBYTE lpEmptyBuffer = nullptr;

	// 判断是否为正常PE头
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(lpDllBuff)->e_magic != IMAGE_DOS_SIGNATURE) {
		return isSuccess;
	}

	// 获取PE结构
	IMAGE_NT_HEADERS* pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(lpDllBuff + reinterpret_cast<IMAGE_DOS_HEADER*>(lpDllBuff)->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = &pOldNtHeader->OptionalHeader;
	IMAGE_FILE_HEADER* pOldFileHeader = &pOldNtHeader->FileHeader;

	// 筛选环境
	if (pOldFileHeader->Machine != CURRENT_ARCH) {
		return isSuccess;
	}

	do {
		// 申请空间
		lpTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!lpTargetBase) {
			break;
		}

		DWORD dwOldProtect = 0;
		VirtualProtectEx(hProc, lpTargetBase, pOldOptHeader->SizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect);
		// 写入PE头，PE头只有前 0x1000 个字节
		if (!WriteProcessMemory(hProc, lpTargetBase, lpDllBuff, 0x1000, nullptr)) {
			break;
		}
		// 写入节表
		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
		if (!WriteSections(hProc, lpDllBuff, lpTargetBase, pSectionHeader, pOldFileHeader)) {
			break;
		}

		// 组装参数
		MANUAL_MAPPING_DATA data{ 0 };
		data.pLoadLibraryA = LoadLibraryA;
		data.pGetProcAddress = GetProcAddress;
#ifdef _WIN64
		data.pRtlAddFunctionTable = (f_RtlAddFunctionTable)RtlAddFunctionTable;
#else
		bSEHExceptionSupport = false;
#endif
		data.pBase = lpTargetBase;
		data.fdwReasonParam = fdwReason;
		data.reservedParam = lpReserved;
		data.SEHSupport = bSEHExceptionSupport;

		// 将我们准备的参数映射到目标进程
		lpParamBuff = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
		if (!lpParamBuff) {
			break;
		}
		if (!WriteProcessMemory(hProc, lpParamBuff, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
			break;
		}

		// 写入shellcode
		lpShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!lpShellcode) {
			break;
		}
		if (!WriteProcessMemory(hProc, lpShellcode, Shellcode, 0x1000, nullptr)) {
			break;
		}

		// 远线程执行shellcode
		HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpShellcode), lpParamBuff, 0, nullptr);
		if (!hThread) {
			break;
		}
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);

		// 获取返回模块地址
		HINSTANCE hModule = NULL;
		hModule = GetReturnModule(hProc, lpParamBuff);
		if (hModule == (HINSTANCE)0x404040) {
			// 参数出错
			break;
		} else if (hModule == (HINSTANCE)0x505050) {
			// 异常支持失败!
		}

		// 申请一片空缓冲区
		lpEmptyBuffer = new BYTE[1024 * 1024 * 20]{};
		if (lpEmptyBuffer == nullptr) {
			break;
		}

		// 清空PE头
		if (bClearHeader) {
			WriteProcessMemory(hProc, lpTargetBase, lpEmptyBuffer, 0x1000, nullptr);
		}

		// 清空无用节点
		if (bClearNonNeededSections) {
			pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
			for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
				if (pSectionHeader->Misc.VirtualSize) {
					if ((bSEHExceptionSupport ? 0 : strcmp((char*)pSectionHeader->Name, ".pdata") == 0) ||
						strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
						strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
						WriteProcessMemory(hProc, lpTargetBase + pSectionHeader->VirtualAddress, lpEmptyBuffer, pSectionHeader->Misc.VirtualSize, nullptr);
					}
				}
			}
		}

		// 调整内存页保护属性
		if (bAdjustProtections) {
			pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
			for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
				if (pSectionHeader->Misc.VirtualSize) {
					DWORD old = 0;
					DWORD newP = PAGE_READONLY;

					if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) > 0) {
						newP = PAGE_READWRITE;
					} else if ((pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0) {
						newP = PAGE_EXECUTE_READ;
					}
					VirtualProtectEx(hProc, lpTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, newP, &old);
				}
			}
			DWORD old = 0;
			VirtualProtectEx(hProc, lpTargetBase, IMAGE_FIRST_SECTION(pOldNtHeader)->VirtualAddress, PAGE_READONLY, &old);
		}

		// 清空shellcode
		WriteProcessMemory(hProc, lpShellcode, lpEmptyBuffer, 0x1000, nullptr);

		isSuccess = true;
	} while (0);

	if (!isSuccess && lpTargetBase != nullptr) {
		VirtualFreeEx(hProc, lpTargetBase, 0, MEM_RELEASE);
	}
	if (lpParamBuff != nullptr) {
		VirtualFreeEx(hProc, lpParamBuff, 0, MEM_RELEASE);
	}
	if (lpShellcode != nullptr) {
		VirtualFreeEx(hProc, lpShellcode, 0, MEM_RELEASE);
	}
	if (lpEmptyBuffer != nullptr) {
		delete[] lpEmptyBuffer;
	}
	return isSuccess;
}

//#pragma runtime_checks( "", off )
//#pragma optimize( "", off )
// 该函数不能与本程序其他任何代码产生关联
// 该函数不能在Debug模式下调试
void __stdcall Shellcode(MANUAL_MAPPING_DATA* lpData) {
	// 检查参数
	if (!lpData) {
		lpData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = lpData->pBase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = lpData->pLoadLibraryA;
	auto _GetProcAddress = lpData->pGetProcAddress;
#ifdef _WIN64
	auto _RtlAddFunctionTable = lpData->pRtlAddFunctionTable;
#endif
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	// 处理重定位表
	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
			while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	// 处理导入表
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				} else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	// 处理tls
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	// 处理异常
	bool ExceptionSupportFailed = false;
#ifdef _WIN64
	if (lpData->SEHSupport) {
		auto excep = pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
		if (excep.Size) {
			if (!_RtlAddFunctionTable(
				reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + excep.VirtualAddress),
				excep.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY), (DWORD64)pBase)) {
				ExceptionSupportFailed = true;
			}
		}
	}
#endif

	// 调用dllmain
	_DllMain(pBase, lpData->fdwReasonParam, lpData->reservedParam);

	if (ExceptionSupportFailed)
		lpData->hMod = reinterpret_cast<HINSTANCE>(0x505050);
	else
		lpData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
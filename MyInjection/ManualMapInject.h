#pragma once
#include <Windows.h>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

// 参数结构体
struct MANUAL_MAPPING_DATA {
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
	BYTE* pBase;
	HINSTANCE hMod;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;
};


/// <summary>
/// 异常支持仅 x64 与构建参数 /EHa 或 /EHc
/// </summary>
/// <param name="hProc">目标进程句柄</param>
/// <param name="lpDllBuff">DLL缓冲区</param>
/// <param name="nFileSize">DLL文件大小</param>
/// <param name="bClearHeader">是否清空PE头，默认为true</param>
/// <param name="bClearNonNeededSections">是否清空无用节点，默认为true</param>
/// <param name="bAdjustProtections">是否调整内存权限，默认为true</param>
/// <param name="bSEHExceptionSupport">SEH异常，默认为true</param>
/// <param name="fdwReason">dllmain参数二</param>
/// <param name="lpReserved">dllmain参数三</param>
/// <returns></returns>
bool ManualMapDll(HANDLE hProc, BYTE* lpDllBuff, SIZE_T nFileSize, bool bClearHeader = true, bool bClearNonNeededSections = true, bool bAdjustProtections = true, bool bSEHExceptionSupport = true, DWORD fdwReason = DLL_PROCESS_ATTACH, LPVOID lpReserved = 0);
void __stdcall Shellcode(MANUAL_MAPPING_DATA* lpData);

class CManualMapInject {
public:
	CManualMapInject();
	virtual ~CManualMapInject();

	/// <summary>
	/// 注入DLL
	/// 注意该DLL的 dllmain 函数必须创建线程干其他事情，否则会卡住注入器获取返回结果
	/// </summary>
	/// <param name="lpDllBuff">DLL缓冲区</param>
	/// <param name="dwFileSize">DLL文件大小</param>
	/// <param name="hProc">目标进程句柄</param>
	/// <returns></returns>
	virtual bool InjectorDLL(LPBYTE lpDllBuff, DWORD dwFileSize, HANDLE hProc);

private:
	// 检查位数是否相同
	bool IsCorrectTargetArchitecture(HANDLE hProc);
};
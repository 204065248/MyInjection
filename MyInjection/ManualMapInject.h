#pragma once
#include <Windows.h>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

// �����ṹ��
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
/// �쳣֧�ֽ� x64 �빹������ /EHa �� /EHc
/// </summary>
/// <param name="hProc">Ŀ����̾��</param>
/// <param name="lpDllBuff">DLL������</param>
/// <param name="nFileSize">DLL�ļ���С</param>
/// <param name="bClearHeader">�Ƿ����PEͷ��Ĭ��Ϊtrue</param>
/// <param name="bClearNonNeededSections">�Ƿ�������ýڵ㣬Ĭ��Ϊtrue</param>
/// <param name="bAdjustProtections">�Ƿ�����ڴ�Ȩ�ޣ�Ĭ��Ϊtrue</param>
/// <param name="bSEHExceptionSupport">SEH�쳣��Ĭ��Ϊtrue</param>
/// <param name="fdwReason">dllmain������</param>
/// <param name="lpReserved">dllmain������</param>
/// <returns></returns>
bool ManualMapDll(HANDLE hProc, BYTE* lpDllBuff, SIZE_T nFileSize, bool bClearHeader = true, bool bClearNonNeededSections = true, bool bAdjustProtections = true, bool bSEHExceptionSupport = true, DWORD fdwReason = DLL_PROCESS_ATTACH, LPVOID lpReserved = 0);
void __stdcall Shellcode(MANUAL_MAPPING_DATA* lpData);

class CManualMapInject {
public:
	CManualMapInject();
	virtual ~CManualMapInject();

	/// <summary>
	/// ע��DLL
	/// ע���DLL�� dllmain �������봴���̸߳��������飬����Ῠסע������ȡ���ؽ��
	/// </summary>
	/// <param name="lpDllBuff">DLL������</param>
	/// <param name="dwFileSize">DLL�ļ���С</param>
	/// <param name="hProc">Ŀ����̾��</param>
	/// <returns></returns>
	virtual bool InjectorDLL(LPBYTE lpDllBuff, DWORD dwFileSize, HANDLE hProc);

private:
	// ���λ���Ƿ���ͬ
	bool IsCorrectTargetArchitecture(HANDLE hProc);
};
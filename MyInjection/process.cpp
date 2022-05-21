#include "process.h"

#include <iostream>
#include <TlHelp32.h>
#include <Windows.h>
#include <Winternl.h>

using namespace std;

#define SystemHandleInformation (SYSTEM_INFORMATION_CLASS)16
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

std::vector<DWORD> CProcess::GetProcessIDByName(const char* name) {
	std::vector<DWORD> pids;
	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE) {
#ifdef _DEBUG
		cout << "创建32位进程快照失败!" << endl;
#endif // _DEBUG
		return pids;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	int flag = Process32First(hsnapshot, &pe);
	while (flag != 0) {
		if (strcmp(pe.szExeFile, name) == 0) {
			pids.push_back(pe.th32ProcessID);
		}
		flag = Process32Next(hsnapshot, &pe);
	}

	CloseHandle(hsnapshot);
	return pids;
}

bool CProcess::SetProcessID(DWORD dwPid) {
	processId = dwPid;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);

	if (!hProcess) {
		return false;
	}
	return true;
}

DWORD CProcess::GetModuleBaseAddress(DWORD dwPid, const char* modName, DWORD* lpModSize) {
	if (!dwPid) {
#ifdef _DEBUG
		cout << "尚未设置进程PID!" << endl;
#endif // _DEBUG
		return NULL;
	}

	DWORD modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPid);
	if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry)) {
			do {
				if (!_stricmp(modEntry.szModule, modName)) {
					modBaseAddr = reinterpret_cast<DWORD>(modEntry.modBaseAddr);
					if (lpModSize != nullptr) {
						*lpModSize = modEntry.modBaseSize;
					}
					break;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
	CloseHandle(hSnap);
	return modBaseAddr;
}

void CProcess::ElevatePrivilegesCurrentProcess() {
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		TOKEN_PRIVILEGES priv = { 0 };
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}
}

auto CProcess::read(DWORD_PTR dwAddress, LPVOID lpcBuffer, DWORD dwSize) -> bool {
	//和ReadProcessMemory用法一致
	return (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(dwAddress), lpcBuffer, dwSize, nullptr) == TRUE);
}

auto CProcess::write(DWORD_PTR dwAddress, LPCVOID lpcBuffer, DWORD dwSize) -> bool {
	return (WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(dwAddress), lpcBuffer, dwSize, nullptr) == TRUE);
}
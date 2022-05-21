#pragma once
#include <Windows.h>
#include <vector>

class CProcess
{
public:
    // 通过进程名获取进程PID
    static std::vector<DWORD> GetProcessIDByName(const char*);
    // 获取该进程的模块地址，模块大小
    static DWORD GetModuleBaseAddress(DWORD dwPid, const char*, DWORD* lpModSize = nullptr);
    // 提示自身进程权限
    static void ElevatePrivilegesCurrentProcess();
    // 设置进程PID
    bool SetProcessID(DWORD);

private:
    // 读取数据
    auto read(DWORD_PTR, LPVOID, DWORD) -> bool;
    // 写入数据
    auto write(DWORD_PTR, LPCVOID, DWORD) -> bool;

public:
    // 读取数据
    template<typename T>
    auto read(const DWORD_PTR& dwAddress, const T& tDefault = T())->T
    {
        T tRet;
        if (!read(dwAddress, &tRet, sizeof(T)))
            return tDefault;
        return tRet;
    }

    // 写入数据
    template<typename T>
    auto write(const DWORD_PTR& dwAddress, const T& tValue) -> bool
    {
        return write(dwAddress, &tValue, sizeof(T));
    }


public:
    // 进程PID
    DWORD processId = NULL;
    // 窗口句柄
    HWND window = nullptr;
    // 进程句柄
    HANDLE hProcess = nullptr;
};
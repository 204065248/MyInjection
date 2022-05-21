#pragma once
#include <Windows.h>
#include <vector>

class CProcess
{
public:
    // ͨ����������ȡ����PID
    static std::vector<DWORD> GetProcessIDByName(const char*);
    // ��ȡ�ý��̵�ģ���ַ��ģ���С
    static DWORD GetModuleBaseAddress(DWORD dwPid, const char*, DWORD* lpModSize = nullptr);
    // ��ʾ�������Ȩ��
    static void ElevatePrivilegesCurrentProcess();
    // ���ý���PID
    bool SetProcessID(DWORD);

private:
    // ��ȡ����
    auto read(DWORD_PTR, LPVOID, DWORD) -> bool;
    // д������
    auto write(DWORD_PTR, LPCVOID, DWORD) -> bool;

public:
    // ��ȡ����
    template<typename T>
    auto read(const DWORD_PTR& dwAddress, const T& tDefault = T())->T
    {
        T tRet;
        if (!read(dwAddress, &tRet, sizeof(T)))
            return tDefault;
        return tRet;
    }

    // д������
    template<typename T>
    auto write(const DWORD_PTR& dwAddress, const T& tValue) -> bool
    {
        return write(dwAddress, &tValue, sizeof(T));
    }


public:
    // ����PID
    DWORD processId = NULL;
    // ���ھ��
    HWND window = nullptr;
    // ���̾��
    HANDLE hProcess = nullptr;
};
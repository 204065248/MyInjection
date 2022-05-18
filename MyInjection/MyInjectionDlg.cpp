
// MyInjectionDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "MyInjection.h"
#include "MyInjectionDlg.h"
#include "afxdialogex.h"

#include "LoadLibraryR.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CMyInjectionDlg 对话框



CMyInjectionDlg::CMyInjectionDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MYINJECTION_DIALOG, pParent) {
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMyInjectionDlg::DoDataExchange(CDataExchange* pDX) {
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CMyInjectionDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(BTN_INJECTION, &CMyInjectionDlg::OnBnClickedInjection)
END_MESSAGE_MAP()


// CMyInjectionDlg 消息处理程序

BOOL CMyInjectionDlg::OnInitDialog() {
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CMyInjectionDlg::OnPaint() {
	if (IsIconic()) {
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	} else {
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CMyInjectionDlg::OnQueryDragIcon() {
	return static_cast<HCURSOR>(m_hIcon);
}



void CMyInjectionDlg::OnBnClickedInjection() {
	char* cpDllFile = "test.dll";
	HANDLE hProcess = NULL;
	LPVOID lpBuffer = NULL;
	do {
		DWORD dwProcessId = GetDlgItemInt(EDT_PID);

		HANDLE hFile = CreateFileA(cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			AfxMessageBox("无法打开 DLL 文件");

		DWORD dwLength = GetFileSize(hFile, NULL);
		if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
			AfxMessageBox("获取 DLL 文件大小失败");

		// 创建缓冲区
		lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
		if (!lpBuffer)
			AfxMessageBox("获取 DLL 文件大小失败");

		// 将DLL数据复制到缓冲区
		DWORD dwBytesRead = 0;
		if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
			AfxMessageBox("分配缓冲区失败!");

		// 进程提权
		HANDLE hToken = NULL;
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
			TOKEN_PRIVILEGES priv = { 0 };
			priv.PrivilegeCount = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
				AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

			CloseHandle(hToken);
		}

		// 打开目标进程
		hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
		if (!hProcess)
			AfxMessageBox("打开目标进程失败");

		// 将DLL写到目标进程，并创建远程线程
		HANDLE hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL);
		if (!hModule)
			AfxMessageBox("注入DLL失败");

		CString strFmt;
		strFmt.Format("[+] 将“%s”DLL 注入进程 %d。", cpDllFile, dwProcessId);
		AfxMessageBox(strFmt);

		WaitForSingleObject(hModule, -1);

	} while (0);

	if (lpBuffer)
		HeapFree(GetProcessHeap(), 0, lpBuffer);

	if (hProcess)
		CloseHandle(hProcess);

}

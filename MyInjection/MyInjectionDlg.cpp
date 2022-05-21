
// MyInjectionDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "MyInjection.h"
#include "MyInjectionDlg.h"
#include "afxdialogex.h"

#include "process.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#include "ManualMapInject.h"

// CMyInjectionDlg 对话框



CMyInjectionDlg::CMyInjectionDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MYINJECTION_DIALOG, pParent) {
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMyInjectionDlg::DoDataExchange(CDataExchange* pDX) {
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, EDT_DLLPATH, m_edtDllPath);
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
	HANDLE hProcess = NULL;
	LPBYTE lpBuffer = NULL;

	CString strDllPath;
	m_edtDllPath.GetWindowText(strDllPath);
	if (strDllPath.GetLength() == 0) {
		AfxMessageBox("请填写需要注入的DLL路径！");
		return;
	}

	do {
		CString strProcessName;
		GetDlgItemText(EDT_PROCESS_NAME, strProcessName);
		if (strProcessName.GetLength() == 0) {
			AfxMessageBox("请填写需要注入的进程名！");
			break;
		}

		auto pids = CProcess::GetProcessIDByName(strProcessName.GetString());
		if (pids.size() == 0) {
			AfxMessageBox("未找到相关进程！");
			break;
		}

		// 进程提权
		CProcess::ElevatePrivilegesCurrentProcess();

		// 打开目标进程
		hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pids[0]);
		if (!hProcess) {
			AfxMessageBox("打开目标进程失败");
			break;
		}

		CFile file;
		file.Open(strDllPath, CFile::modeRead);
		ULONGLONG nFileSize = file.GetLength();
		lpBuffer = new BYTE[nFileSize]{};
		file.SeekToBegin();
		file.Read(lpBuffer, nFileSize);
		file.Close();

		CManualMapInject inject;
		if (inject.InjectorDLL(lpBuffer, nFileSize, hProcess)) {
			AfxMessageBox("注入成功");
		} else {
			AfxMessageBox("注入失败");
		}


	} while (0);

	if (lpBuffer != nullptr) {
		delete[] lpBuffer;
	}

	if (hProcess != NULL) {
		CloseHandle(hProcess);
	}
}

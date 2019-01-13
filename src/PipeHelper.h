#pragma once

#include <windows.h>
#include <atlconv.h>
#include <string>
#include <tchar.h>

#if !defined(_UNICODE) && !defined(UNICODE)
#define TSTRING std::string
#else
#define TSTRING std::wstring
#endif

#define tstring TSTRING
#define _tstring TSTRING

#define WAIT_PROCESS_TIMEOUT	10000

class CPipeHelper
{
public:
	CPipeHelper();
	~CPipeHelper();

private:
	HANDLE m_hScriptFile;//脚本句柄

	HANDLE m_hStdInReader;//标准读输入流
	HANDLE m_hStdInWriter;//标准写输入流
	HANDLE m_hStdOutReader;//标准读输出流
	HANDLE m_hStdOutWriter;//标准读输出流

	STARTUPINFO m_siStartInfo;//进程启动信息
	PROCESS_INFORMATION m_piProcessInfo;//进程启动信息

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:创建子应用进程
	//函数参数:
	//		lpApplicationName	应用程序名称
	//		lpCommandLine		程序运行参数
    //      dwMilliseconds		子进程启动超时时间,单位为毫秒
	//返回值:
	//	0,		成功
	//	(-1),	创建进程失败
	int CreateChildProcess(LPCTSTR lpApplicationName, LPTSTR lpCommandLine = NULL, DWORD dwMilliseconds = WAIT_TIMEOUT);

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:读取脚本命令执行结果
	//函数参数:
	//返回值:
	void ReadFromPipe(void);

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:脚本写入命令
	//函数参数:
	//返回值:
	void WriteToPipe(void);

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:写入命令并取得执行结果
	//函数参数:
	//		tsInputCommand	要写入的命令(内容处理会加入'\r\n')
	//返回值:
	//		失败返回空,成功返回执行结果
	TSTRING WritePipeAndReadPipe(TSTRING tsInputCommand);

public:
	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:初始化管道操作类
	//函数参数:
	//		lpApplicationName	应用程序名称
	//		lpCommandLine		程序运行参数
    //      dwMilliseconds		子进程启动超时时间,单位为毫秒
	//返回值:
	//	0,		成功
	//	(-1),	打开脚本文件失败
	int Initialize(LPCTSTR lpApplicationName, LPTSTR lpCommandLine = NULL, DWORD dwMilliseconds = WAIT_TIMEOUT);

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:释放掉管道操作类
	//函数参数:
	//返回值:
	void Exitialize();

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:初始化管道脚本
	//函数参数:
	//		tsScriptName	脚本文件路径名
	//返回值:
	//	0,		成功
	//	(-1),	打开脚本文件失败
	int InitScript(TSTRING tsScriptFileName);

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:读取脚本命令执行结果
	//函数参数:
	//返回值:
	void Read();

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:脚本写入命令
	//函数参数:
	//返回值:
	void Write();

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:读取初始化执行结果
	//函数参数:
	//		无
	//返回值:
	//		失败返回空,成功返回执行结果
	TSTRING ReadPipeFromInit();

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:写入命令并取得执行结果
	//函数参数:
	//		tsInputCommand	要写入的命令(内容处理会加入'\r\n')
	//返回值:
	//		失败返回空,成功返回执行结果
	TSTRING WriteAndRead(TSTRING tsInputCommand);

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//函数功能:静态执行命令并取得执行结果
	//函数参数:
	//		lpApplicationName	应用程序名称
	//		lpCommandLine		要写入的命令(内容处理会加入'\r\n')
	//      dwMilliseconds		子进程启动超时时间,单位为毫秒
	//返回值:
	//		失败返回"_ERROR_FAILURE_",成功返回执行结果
	static TSTRING RunCmd(LPCTSTR lpApplicationName, LPTSTR lpCommandLine = NULL, DWORD dwMilliseconds = WAIT_TIMEOUT);
};

CPipeHelper::CPipeHelper()
{
	m_hScriptFile = NULL;

	m_hStdInReader = NULL;
	m_hStdInWriter = NULL;
	m_hStdOutReader = NULL;
	m_hStdOutWriter = NULL;
}

CPipeHelper::~CPipeHelper()
{

}

/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:初始化管道操作类
//函数参数:
//		lpApplicationName	应用程序名称
//		lpCommandLine		程序运行参数
//      dwMilliseconds		子进程启动超时时间,单位为毫秒
//返回值:
//	0,		成功
//	(-1),	打开脚本文件失败
int CPipeHelper::Initialize(LPCTSTR lpApplicationName, LPTSTR lpCommandLine/* = NULL*/, DWORD dwMilliseconds/* = WAIT_TIMEOUT*/)
{
	int result = 0;

	SECURITY_ATTRIBUTES saAttr = { 0 };

	OutputDebugString(_T("\n->Start of parent execution.\n"));

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Create a pipe for the child process's STDOUT.
	if (!CreatePipe(&m_hStdOutReader, &m_hStdOutWriter, &saAttr, 0))
	{
		return (-1);
	}

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	if (!SetHandleInformation(m_hStdOutReader, HANDLE_FLAG_INHERIT, 0))
	{
		return (-2);
	}
	// Create a pipe for the child process's STDIN.
	if (!CreatePipe(&m_hStdInReader, &m_hStdInWriter, &saAttr, 0))
	{
		return (-3);
	}

	// Ensure the write handle to the pipe for STDIN is not inherited.
	if (!SetHandleInformation(m_hStdInWriter, HANDLE_FLAG_INHERIT, 0))
	{
		return (-4);
	}

	// Create the child process.
	result = CreateChildProcess(lpApplicationName, lpCommandLine, dwMilliseconds);
	if (result != 0)
	{
		return (-5);
	}
	
	return result;
}


/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:创建子应用进程
//函数参数:
//		lpApplicationName	应用程序名称
//		lpCommandLine		程序运行参数
//      dwMilliseconds		子进程启动超时时间,单位为毫秒
//返回值:
//	0,		成功
//	(-1),	创建进程失败
int CPipeHelper::CreateChildProcess(LPCTSTR lpApplicationName, LPTSTR lpCommandLine/* = NULL*/, DWORD dwMilliseconds/* = WAIT_TIMEOUT*/)
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
{
	int result = 0;
	BOOL bSuccess = FALSE;

	// Set up members of the PROCESS_INFORMATION structure.
	ZeroMemory(&m_piProcessInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure.
	// This structure specifies the STDIN and STDOUT handles for redirection.
	ZeroMemory(&m_siStartInfo, sizeof(STARTUPINFO));
	m_siStartInfo.cb = sizeof(STARTUPINFO);
	m_siStartInfo.hStdError = m_hStdOutWriter;
	m_siStartInfo.hStdOutput = m_hStdOutWriter;
	m_siStartInfo.hStdInput = m_hStdInReader;
	m_siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
	// hide window flag
	m_siStartInfo.dwFlags |= STARTF_USESHOWWINDOW;
	// hide window
	m_siStartInfo.wShowWindow = SW_HIDE;

	// Create the child process.
	bSuccess = CreateProcess(lpApplicationName,// application name
		lpCommandLine,     // command line
		NULL,          // process security attributes
		NULL,          // primary thread security attributes
		TRUE,          // handles are inherited
		0,             // creation flags
		NULL,          // use parent's environment
		NULL,          // use parent's current directory
		&m_siStartInfo,  // STARTUPINFO pointer
		&m_piProcessInfo// receives PROCESS_INFORMATION
	);
	// If an error occurs, exit the application.
	if (!bSuccess)
	{
		return (-1);
	}
	else
	{
		// Wait until child process exits.
		WaitForSingleObject(m_piProcessInfo.hProcess, dwMilliseconds);
	}

	return result;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:读取脚本命令执行结果
//函数参数:
//返回值:
void CPipeHelper::ReadFromPipe(void)

// Read output from the child process's pipe for STDOUT
// and write to the parent process's pipe for STDOUT.
// Stop when there is no more data.
{
	BOOL bSuccess = FALSE;
	DWORD dwBytesRead = 0L;
	DWORD dwBytesWritten = 0L;
	CHAR chBuf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE] = { 0 };
	HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

	while (true)
	{
		bSuccess = ReadFile(m_hStdOutReader, chBuf, sizeof(chBuf) / sizeof(*chBuf), &dwBytesRead, NULL);
		if (!bSuccess || dwBytesRead <= 0)
		{
			break;
		}
		bSuccess = WriteFile(hParentStdOut, chBuf, dwBytesRead, &dwBytesWritten, NULL);
		if (!bSuccess)
		{
			break;
		}
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:脚本写入命令
//函数参数:
//返回值:
void CPipeHelper::WriteToPipe(void)
// Read from a file and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data.
{
	BOOL bSuccess = FALSE;
	DWORD dwBytesRead = 0L;
	DWORD dwBytesWritten = 0L;
	CHAR chBuf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE] = { 0 };

	while(true)
	{
		bSuccess = ReadFile(m_hScriptFile, chBuf, sizeof(chBuf) / sizeof(*chBuf), &dwBytesRead, NULL);
		if (!bSuccess || dwBytesRead <= 0)
		{
			break;
		}
		bSuccess = WriteFile(m_hStdInWriter, chBuf, dwBytesRead, &dwBytesWritten, NULL);
		if (!bSuccess)
		{
			break;
		}
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:写入命令并取得执行结果
//函数参数:
//		tsInputCommand	要写入的命令(内容处理会加入'\r\n')
//返回值:
//		失败返回空,成功返回执行结果
TSTRING CPipeHelper::WritePipeAndReadPipe(TSTRING tsInputCommand)
// Read from a file and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data.
{
	BOOL bSuccess = FALSE;
	DWORD dwBytesRead = 0L;
	DWORD dwBytesWritten = 0L;
	DWORD dwTotalBytesAvail = 0L;
	DWORD dwBytesLeftThisMessage = 0L;
	std::string strOutput = "";
	std::string strInputCommand = "";
	CHAR chBuf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE] = { 0 };

	USES_CONVERSION_EX;

	strInputCommand = T2A_EX((LPTSTR)tsInputCommand.c_str(), tsInputCommand.length());
	strInputCommand.append("\r\n");
	bSuccess = WriteFile(m_hStdInWriter, strInputCommand.c_str(), strInputCommand.length(), &dwBytesWritten, NULL);
	if (!bSuccess)
	{
		return _T("");
	}

	while(true)
	{
		memset(chBuf, 0, sizeof(chBuf));
		bSuccess = PeekNamedPipe(m_hStdOutReader, chBuf, sizeof(*chBuf), &dwBytesRead, &dwTotalBytesAvail, &dwBytesLeftThisMessage);
		if (!bSuccess || dwBytesRead <= 0)
		{
			break;
		}

		//无数据时会阻塞，不采用
		bSuccess = ReadFile(m_hStdOutReader, chBuf, sizeof(chBuf) / sizeof(*chBuf), &dwBytesRead, NULL);
		if (!bSuccess || dwBytesRead <= 0)
		{
			break;
		}
		strOutput.append(chBuf);
	}

	if (strOutput.length() <= 0)
	{
		return _T("");
	}

	return TSTRING(A2T_EX((LPSTR)strOutput.c_str(), strOutput.length()));
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:释放掉管道操作类
//函数参数:
//返回值:
void CPipeHelper::Exitialize()
{
	// Close the script file handle so the child process stops reading.
	if (m_hScriptFile)
	{
		CloseHandle(m_hScriptFile);
		m_hScriptFile = NULL;
	}

	// Close handles to the child process and its primary thread.
	// Some applications might keep these handles to monitor the status
	// of the child process, for example.
	if (m_piProcessInfo.hProcess)
	{
		TerminateProcess(m_piProcessInfo.hProcess, (0));
		CloseHandle(m_piProcessInfo.hProcess);
		m_piProcessInfo.hProcess = NULL;
	}
	if (m_piProcessInfo.hThread)
	{
		TerminateThread(m_piProcessInfo.hThread, (0));
		CloseHandle(m_piProcessInfo.hThread);
		m_piProcessInfo.hThread = NULL;
	}
	
	// Close the pipe handle so the child process stops reading.
	if (m_hStdInReader)
	{
		CloseHandle(m_hStdInReader);
		m_hStdInReader = NULL;
	}
	if (m_hStdInWriter)
	{
		CloseHandle(m_hStdInWriter);
		m_hStdInWriter = NULL;
	}
	if (m_hStdOutReader)
	{
		CloseHandle(m_hStdOutReader);
		m_hStdOutReader = NULL;
	}
	if (m_hStdOutWriter)
	{
		CloseHandle(m_hStdOutWriter);
		m_hStdOutWriter = NULL;
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:初始化脚本内容读取
//函数参数:
//		tsScriptName	脚本文件路径名
//返回值:
//	0,		成功
//	(-1),	打开脚本文件失败
int CPipeHelper::InitScript(TSTRING tsScriptName)
{
	int result = 0;

	// Get a handle to an input file for the parent.
	// This example assumes a plain text file and uses string output to verify data flow.
	m_hScriptFile = CreateFile(
		tsScriptName.c_str(),
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_READONLY,
		NULL);

	if (m_hScriptFile == INVALID_HANDLE_VALUE)
	{
		return (-1);
	}

	return result;
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:读取脚本命令执行结果
//函数参数:
//返回值:
void CPipeHelper::Read()
{
	ReadFromPipe();
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:脚本写入命令
//函数参数:
//返回值:
void CPipeHelper::Write()
{
	WriteToPipe();
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:读取初始化执行结果
//函数参数:
//		无
//返回值:
//		失败返回空,成功返回执行结果
TSTRING CPipeHelper::ReadPipeFromInit()
// Read from a file and write its contents to the pipe for the child's STDIN.
// Stop when there is no more data.
{
	BOOL bSuccess = FALSE;
	DWORD dwBytesRead = 0L;
	std::string strOutput = "";
	DWORD dwTotalBytesAvail = 0L;
	DWORD dwBytesLeftThisMessage = 0L;
	CHAR chBuf[MAXIMUM_REPARSE_DATA_BUFFER_SIZE] = { 0 };
	
	USES_CONVERSION_EX;

	while(true)
	{
		memset(chBuf, 0, sizeof(chBuf));
		bSuccess = PeekNamedPipe(m_hStdOutReader, chBuf, sizeof(*chBuf), &dwBytesRead, &dwTotalBytesAvail, &dwBytesLeftThisMessage);
		if (!bSuccess || dwBytesRead <= 0)
		{
			break;
		}

		//无数据时会阻塞，不采用
		bSuccess = ReadFile(m_hStdOutReader, chBuf, sizeof(chBuf) / sizeof(*chBuf), &dwBytesRead, NULL);
		if (!bSuccess || dwBytesRead <= 0)
		{
			break;
		}
		strOutput.append(chBuf);
	}

	if (strOutput.length() <= 0)
	{
		return _T("");
	}

	return TSTRING(A2T_EX((LPSTR)strOutput.c_str(), strOutput.length()));
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:写入命令并取得执行结果
//函数参数:
//		tsInputCommand	要写入的命令(内容处理会加入'\r\n')
//返回值:
//		失败返回空,成功返回执行结果
TSTRING CPipeHelper::WriteAndRead(TSTRING tsInputCommand)
{
	return WritePipeAndReadPipe(tsInputCommand);
}

/////////////////////////////////////////////////////////////////////////////////////////////////
//函数功能:静态执行命令并取得执行结果
//函数参数:
//		lpApplicationName	应用程序名称
//		lpCommandLine		要写入的命令(内容处理会加入'\r\n')
//      dwMilliseconds		子进程启动超时时间,单位为毫秒
//返回值:
//		失败返回"__ERROR_WRONG__",成功返回执行结果
TSTRING CPipeHelper::RunCmd(LPCTSTR lpApplicationName, LPTSTR lpCommandLine/* = NULL*/, DWORD dwMilliseconds/* = WAIT_TIMEOUT*/)
{
	CPipeHelper pipeHelper;
	TSTRING tsResult = _T("__ERROR_WRONG__");//初始化为错误字符串

	if (!pipeHelper.Initialize(lpApplicationName, lpCommandLine, dwMilliseconds))
	{
		tsResult = pipeHelper.ReadPipeFromInit();
	}
	pipeHelper.Exitialize();

	return tsResult;
}

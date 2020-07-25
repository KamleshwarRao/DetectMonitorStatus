// DetectMonitorStatus.cpp : Implementation of WinMain
//////////////////////////////////////////////////////////////////////////////////////////////
// Product Name: Detect Monitor Status
// Developed By: N Kamleshwar Rao
// Dated Created: 19th July 2020
// Last Modified: 24th July 2020
//
// Description:
// This is a ATL based Windows Service that monitors the Display being idle or System's 
// getting idle and based on that collects monitoring information such as Computer Name, 
// TimeStamp and Public IP of the Computer.
//////////////////////////////////////////////////////////////////////////////////////////////

#include "pch.h"
#include "framework.h"
#include "resource.h"
#include "DetectMonitorStatus_i.h"
#include <string>
#include "Shlobj.h"
#include "dbt.h"
#include "WTSapi32.h"
#include "userenv.h"

#define RECYCLE_PERIOD		-10000000LL * 60 * 5
#define RECYCLE_TIMER		_T ( "Recycle Timer" )
#define PATH_SIZE			4096
#define MAX_IPV4			16
#define BUFSIZE				4096
#define VARNAME				_T ( "data" )


TCHAR szFileName[PATH_SIZE] = { 0 };
HANDLE hDisplayOffEvent = NULL;
HANDLE hTerminateEvent = NULL;

HANDLE hTimer = NULL;
LARGE_INTEGER liDueTime = { 0 } ;

HANDLE hDisplayTimerThread = NULL;
using namespace ATL;

#include <stdio.h>

DWORD WINAPI DisplayTimerThread(LPVOID pData);
void GetPublicIPAddress(TCHAR* szIPAddress);
DWORD WINAPI SystemNotificationHandler(DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext);

class CDetectMonitorStatusModule : public ATL::CAtlServiceModuleT< CDetectMonitorStatusModule, IDS_SERVICENAME >
{
public :
	DECLARE_LIBID(LIBID_DetectMonitorStatusLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_DETECTMONITORSTATUS, "{f94fd8db-86d3-4e6e-9c8c-5634a50f8add}")
	HRESULT InitializeSecurity() throw()
	{
		// TODO : Call CoInitializeSecurity and provide the appropriate security settings for your service
		// Suggested - PKT Level Authentication,
		// Impersonation Level of RPC_C_IMP_LEVEL_IDENTIFY
		// and an appropriate non-null Security Descriptor.

		return S_OK;
	}

	HRESULT PreMessageLoop(int nShowCmd)
	{
		SetServiceStatus(SERVICE_RUNNING);
		return __super::PreMessageLoop(nShowCmd);
	}

	void ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv);
	void Handler(DWORD dwOpcode);
	HRESULT Run(_In_ int nShowCmd = SW_HIDE) throw();	
};

CDetectMonitorStatusModule _AtlModule;



//
extern "C" int WINAPI _tWinMain(HINSTANCE /*hInstance*/, HINSTANCE /*hPrevInstance*/,
								LPTSTR /*lpCmdLine*/, int nShowCmd)
{
	//_AtlModule.ServiceMain(2, L"");
	return _AtlModule.WinMain(nShowCmd);
}

DWORD WINAPI SystemNotificationHandler ( DWORD dwControl, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext )
{
	OutputDebugString(_T("DetectMonitorStatus: SystemNotificationHandler"));

	PPOWERBROADCAST_SETTING pws;
	if ( dwControl == SERVICE_CONTROL_POWEREVENT )
	{
		OutputDebugString(_T("Received Power Event"));
		switch (dwEventType)
		{
			case PBT_POWERSETTINGCHANGE:
			{
				pws = (PPOWERBROADCAST_SETTING)lpEventData;

				if (pws->PowerSetting == GUID_CONSOLE_DISPLAY_STATE)
				{
					//On Display Off, Set the Event
					if ((BYTE)pws->Data[0] == 0)
					{
						OutputDebugString(_T("Display Turned Off"));
						SetEvent(hDisplayOffEvent); 
					}
					else if ((BYTE)pws->Data[0] == 1)
					{
						OutputDebugString(_T("Display Turned On"));
						ResetEvent(hDisplayOffEvent);
						CancelWaitableTimer(hTimer);

						//Write Wake up Logic
						if (_tcslen(szFileName) && PathFileExists(szFileName))
						{
							if (DeleteFile(szFileName))
							{
								OutputDebugString(_T("File Deleted"));
								if (NULL != hTimer)
								{
									// Set a timer to wait for 5 mins.
									//if (!SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0))
									{
										//printf("SetWaitableTimer failed (%d)\n", GetLastError());
										return 0;
									}
								}
								return 0;
							}
						}
					}
				}
			}
			break;
			case PBT_APMSUSPEND: //This is required to be handled so that we can handle PBT_APMRESUMESUSPEND, otherwise PBT_APMRESUMECRITICAL would be thrown
			{
				//Dummy, but required

				//Debug and Check, whether the following lines of code is required or not.
				pws = (PPOWERBROADCAST_SETTING)lpEventData;

				if (pws->PowerSetting == GUID_CONSOLE_DISPLAY_STATE)
				{
					//On Display Off, Set the Event
					if ((BYTE)pws->Data[0] == 0)
					{
						SetEvent(hDisplayOffEvent);
					}
				}
			}
			break;
			case PBT_APMRESUMESUSPEND:
			{
				pws = (PPOWERBROADCAST_SETTING)lpEventData;

				if (pws->PowerSetting == GUID_CONSOLE_DISPLAY_STATE)
				{
					//On Display On, Set the Event
					if ((BYTE)pws->Data[0] == 1)
					{
						OutputDebugString(_T("Display Turned On"));
						ResetEvent(hDisplayOffEvent);
						CancelWaitableTimer(hTimer);

						//Write Wake up Logic
						if (_tcslen(szFileName) && PathFileExists(szFileName))
						{
							//if (DeleteFile(szFileName))
							{
								if (NULL != hTimer)
								{
									// Set a timer to wait for 5 mins.
									//if (!SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0))
									{
										//printf("SetWaitableTimer failed (%d)\n", GetLastError());
										return 0 ;
									}
								}
								return 0;
							}
						}
					}
				}
			}
			break;

		}
	}
	
	return 0;
}

void CDetectMonitorStatusModule::ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
	// TODO: Add your specialized code here and/or call the base class
	//  The Windows Service needs to register for power events of system state transitioning.
	//	On Display Idle Timer times out, then Service will get notification from the System for going into Sleep state and will turn off the display.
	//	During this handling a text file would be created with the Time Stampand update it with Computer Name and its Location details.PBT_APMSUSPEND is the event that would be sent by the System during this timeand the handler needs to perform the task i.e.writing information to the file in 2 seconds.
	//	Now to identify the Wake up - If the system wakes due to user activity(sends PBT_APMRESUMEAUTOMATIC event followed by a PBT_APMRESUMESUSPEND event), the system does not automatically return to sleep based on the unattended idle timer.Instead the system returns to sleep based on the system idle timer.
	//	On Wakeup detected by the Service the delete the created file and enters into the idle state for a configurable time with some configurator application.
	//	Once the Time elapses, the detection cycle continues.

	//ServiceMain should have the following:
	//Register Power Setting Notification - Coding Done
	//	Handler will receive the Power Setting Notification
	//Create a Periodic Timer - Coding Done
	//Handle Display Off or Sleep event through the Handler - Coding Done, except IP Address
	//	Create File (Kiewit.txt) with Time Stamp and Computer Name and IP Location
	//Handle Display On or Wake up event through the Handler - Coding Done
	//	Delete the created File
	//Cycle the Periodic Timer	- Coding Done for Timer, but needs to be placed in a separate Thread
	hDisplayOffEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

	//**************************************************
	//Create a Waitable Timer
#if 0
	HANDLE hWait = ::CreateWaitableTimer(NULL, TRUE, RECYCLE_TIMER);

	if (NULL != hWait)
	{

	}
	//HANDLE hTimer = NULL;
	//LARGE_INTEGER liDueTime;

	liDueTime.QuadPart = RECYCLE_PERIOD;

	// Create an named waitable timer.
	hTimer = CreateWaitableTimer(NULL, TRUE, RECYCLE_TIMER);
	if (NULL == hTimer)
	{
		LogEvent (_T("CreateWaitableTimer failed (%d)\n"), GetLastError());
		return;
	}

	// Set a timer to wait for 5 mins.
	if (!SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0))
	{
		LogEvent(_T("SetWaitableTimer failed (%d)\n"), GetLastError());
		return;
	}
#endif

	__super::ServiceMain(dwArgc, lpszArgv);
}


void CDetectMonitorStatusModule::Handler(DWORD dwOpcode)
{
	// TODO: Add your specialized code here and/or call the base class
	__super::Handler(dwOpcode);
}

HRESULT CDetectMonitorStatusModule::Run(int nShowCmd)
{
	//Create the Worker Thread and wait for it infinitely
	DWORD dwThreadId = 0;
	hDisplayTimerThread = CreateThread(NULL, 0, DisplayTimerThread, NULL, 0, &dwThreadId);

	return __super::Run(0);
}
DWORD WINAPI DisplayTimerThread(LPVOID pData)
{
	
	OutputDebugString(_T("DisplayTimerThread up and running"));
	SERVICE_STATUS_HANDLE hService = RegisterServiceCtrlHandlerEx(_T("DetectMonitorStatus"), SystemNotificationHandler, (LPVOID)NULL); //lpContext to receive the Data to process
	if (hService == NULL) {
		OutputDebugString(_T("Unable to Register the SystemNotificationHandler"));
		return 1;
	}

	SERVICE_STATUS ssh = { 0 };// SERVICE_START_PENDING;

	SetServiceStatus(hService, &ssh);

	DEV_BROADCAST_HANDLE32 NotificationFilter;
	ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));
	NotificationFilter.dbch_size = sizeof(DEV_BROADCAST_HANDLE32);
	NotificationFilter.dbch_devicetype = DBT_DEVTYP_HANDLE;

	HDEVNOTIFY hDevNotify = RegisterDeviceNotification(hService, &NotificationFilter, DEVICE_NOTIFY_SERVICE_HANDLE);
	if (NULL == hDevNotify)
	{
		OutputDebugString(_T("Unable to Register the DeviceNotification"));
		//return;
	}

	//Register Power Setting Notification Infrastructure
	//  The Windows Service needs to register for power events of system state transitioning.
	LPCGUID PowerSettingGuid = &GUID_CONSOLE_DISPLAY_STATE;
	HPOWERNOTIFY hPwrNotify = RegisterPowerSettingNotification(hService, PowerSettingGuid, DEVICE_NOTIFY_SERVICE_HANDLE);
	if (hPwrNotify == NULL) {
		OutputDebugString(_T("Unable to Register the Power Setting Notification"));
		return 1;
	}

	//while (1)
	{
		
		//Run for the First Time by checking the Display
		//Wait 
		//	On Display Idle Timer times out, then Service will get notification from the System for going into Sleep stateand will turn off the display.
		while (1) //WAIT_OBJECT_0 == WaitForSingleObject(hTimer, 500))
		{
			if (WAIT_OBJECT_0 == WaitForSingleObject(hDisplayOffEvent, INFINITE/*1000*/))
			{
				//The Display is Off
				//	During this handling a text file would be created with the Time Stamp and update it with Computer Name and its Location details.
				//PBT_APMSUSPEND is the event that would be sent by the System during this time and the handler needs to perform the task 
				//i.e.writing information to the file in 2 seconds.
				SYSTEMTIME st;
				GetLocalTime(&st);

				std::string fmtStr;
				TCHAR szTimeStamp[MAX_PATH] = { 0 };
				swprintf_s(szTimeStamp, MAX_PATH, _T("%.2d/%.2d/%.2d %.2d:%.2d:%.2d"), st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

				TCHAR szComputerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
				DWORD dwSize = sizeof(TCHAR) * (MAX_COMPUTERNAME_LENGTH + 1);
				GetComputerName(szComputerName, &dwSize);

				PWSTR szPath = NULL ; 
				HANDLE hToken = NULL;
				OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
				HRESULT hRes = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, hToken, &szPath);

				if (SUCCEEDED(hRes))
				{
					TCHAR szIPAddress[MAX_IPV4] = { 0 };
					GetPublicIPAddress(szIPAddress);

					_tcscpy_s(szFileName, MAX_PATH * sizeof(TCHAR), ( TCHAR *)szPath);

					PathAppend(szFileName, _T("Kiewit.txt"));

					FILE* fp = NULL;
					int err = _wfopen_s(&fp, szFileName, _T("w"));
					OutputDebugString(_T("szFileName"));
					OutputDebugString(szFileName);
					if (!err)
					{
						_ftprintf_s(fp, _T("%s %s %s"), szTimeStamp, szComputerName, szIPAddress);
						OutputDebugString(szTimeStamp);
						OutputDebugString(szComputerName);
						OutputDebugString(szIPAddress);
					}

					ResetEvent(hDisplayOffEvent);

					if ( NULL != fp )
						fclose(fp);

					CoTaskMemFree(szPath);
				}

				//break;
			}

			Sleep(2000);
		}

		//	Now to identify the Wake up - If the system wakes due to user activity(sends PBT_APMRESUMEAUTOMATIC event followed by a PBT_APMRESUMESUSPEND event), the system does not automatically return to sleep based on the unattended idle timer.Instead the system returns to sleep based on the system idle timer.
		//	On Wakeup detected by the Service the delete the created file and enters into the idle state for a configurable time with some configurator application.
#if 0
		// Set a timer to wait for 5 mins.
		if (!SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, 0))
		{
			//LogEvent(_T("SetWaitableTimer failed (%d)\n"), GetLastError());
			return -1;
		}
#endif

		// Wait for the timer.
		/*if (WaitForSingleObject(hTimer, INFINITE) != WAIT_OBJECT_0)
			printf("WaitForSingleObject failed (%d)\n", GetLastError());
		else printf("Timer was signaled.\n");*/
	}

	return 0;
}

void GetPublicIPAddress(TCHAR* szIPAddress)
{
	PWSTR szPath = NULL; 
	HANDLE hToken = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	HRESULT hRes = SHGetKnownFolderPath(FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, hToken, &szPath);

	if (SUCCEEDED(hRes))
	{
		PathAppend(szPath, _T("Kiewit"));
		_tcscpy_s(szFileName, MAX_PATH * sizeof(TCHAR), szPath);
		
		if (!PathFileExists(szFileName))
		{
			SHCreateDirectoryEx(NULL, szFileName, NULL);
		}

		SetCurrentDirectory(szFileName);

		PathAppend(szFileName, _T("getip.bat"));

		FILE* fp = NULL;
		int err = _wfopen_s(&fp, szFileName, _T("w"));

		if (!err)
		{
			OutputDebugString(szFileName);
			_ftprintf_s(fp, _T("@echo off\ncd %s\nnslookup myip.opendns.com resolver1.opendns.com > publicip.txt\nFIND \"Address\" publicip.txt > OnlyIP.txt\nfor /F \"skip=3 delims=\" %%%%i in (OnlyIP.txt) do set data = \"%%%%i\"\nFOR /f \"tokens=1,2 delims=:\" %%%%a IN(\"%%data%%\") do set data = %%%%b\nset data = %%data:~1,-1%%\necho %%data%% > OnlyIP.txt\n"), szPath);
			//_ftprintf_s(fp, _T("@echo on\nfor /F \"skip=3 delims=\" %%%%i in (OnlyIP.txt) do set data = \"%%%%i\"\nFOR /f \"tokens=1,2 delims=:\" %%%%a IN(\"%%data%%\") do set data = %%%%b\nset data = %%data:~1,-1%%\nreg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DetectMonitorStatus /v IPAddress /t REG_SZ /d %%data%%\nmore\n"));
		}

		fclose(fp);
	}

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	LPTSTR pszOldVal = new TCHAR[BUFSIZE] ;
	DWORD dwRet = GetEnvironmentVariable(VARNAME, pszOldVal, BUFSIZE);
	DWORD dwErr;
	BOOL fExist = FALSE;
	if (0 == dwRet)
	{
		dwErr = GetLastError();
		if (ERROR_ENVVAR_NOT_FOUND == dwErr)
		{
			OutputDebugString(_T("Environment variable does not exist.\n"));
			fExist = FALSE;
		}
	}
	else if (BUFSIZE < dwRet)
	{
		delete[] pszOldVal;
		pszOldVal = (LPTSTR)new TCHAR[ dwRet ];
		if (NULL == pszOldVal)
		{
			printf("Out of memory\n");
			return ;
		}
		dwRet = GetEnvironmentVariable(VARNAME, pszOldVal, dwRet);
		if (!dwRet)
		{
			printf("GetEnvironmentVariable failed (%d)\n", GetLastError());
			return ;
		}
		else fExist = TRUE;
	}
	else 
		fExist = TRUE;

	// Set a value for the child process to inherit. 

	if (!SetEnvironmentVariable(VARNAME, TEXT("IP")))
	{
		printf("SetEnvironmentVariable failed (%d)\n", GetLastError());
		return ;
	}
#if 0
	/*HANDLE*/ hToken = INVALID_HANDLE_VALUE;
	PWTS_SESSION_INFO pwsi = nullptr;
	DWORD dwCount = 0;

	if (WTSEnumerateSessions(WTS_CURRENT_SERVER, 0, 1, &pwsi, &dwCount))
	{
		for (DWORD i = 0; i < dwCount; i++)
		{
			PWTS_SESSION_INFO pi = &pwsi[i];
			if (pi->State == WTSActive)
			{
				WTSQueryUserToken(pi->SessionId, &hToken);
				break;
			}
		}
	}

	if (pwsi)
		WTSFreeMemory(pwsi);

	LPVOID lpEnvironment = nullptr;
	if (hToken != INVALID_HANDLE_VALUE)
	{
		//LPVOID lpEnvironment = nullptr;
		LPWSTR pszPath = nullptr;

		//if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, 0, hToken, &pszPath))) // Get Documents Folder to set as working directory
		{
			if (CreateEnvironmentBlock(&lpEnvironment, hToken, FALSE))
			{
				TCHAR szCmd[BUFSIZE] = { _T("cmd /C ") };
				_tcscat_s(szCmd, MAX_PATH * sizeof(TCHAR), szFileName);

				STARTUPINFO si = { sizeof(STARTUPINFO) };
				PROCESS_INFORMATION pi;

				if (CreateProcessAsUser(hToken, szCmd, nullptr, nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT,
					lpEnvironment, pszPath, &si, &pi))
				{
					/*CloseHandle(pi.hThread);
					CloseHandle(pi.hProcess);*/
				}

				//DestroyEnvironmentBlock(lpEnvironment);
			}

			//CoTaskMemFree(pszPath);
		}

		CloseHandle(hToken);
	}
#endif

//#if 0
	// Start the child process. 
	TCHAR szCmd[BUFSIZE] = { _T("cmd /C " ) }; //cmd /C 
	_tcscat_s(szCmd, MAX_PATH * sizeof(TCHAR), szFileName);
#if 0
	if (!CreateProcess(NULL,   // No module name (use command line)
		szCmd,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		CREATE_UNICODE_ENVIRONMENT|CREATE_NEW_CONSOLE,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		return;
	}
#endif
	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	SHELLEXECUTEINFO shExeInfo = { 0 } ;
	shExeInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	shExeInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	shExeInfo.hwnd = NULL;
	shExeInfo.lpVerb = L"open";
	shExeInfo.lpFile = szCmd;
	//shExeInfo.lpParameters = L"\"test param\"";
	shExeInfo.lpDirectory = NULL;
	shExeInfo.nShow = SW_SHOW;
	shExeInfo.hInstApp = NULL;
	ShellExecuteEx(&shExeInfo);

	WaitForSingleObject(shExeInfo.hProcess, INFINITE);


	_tcscpy_s(szFileName, MAX_PATH * sizeof(TCHAR), szPath);

	PathAppend(szFileName, _T("OnlyIP.txt"));
	if (PathFileExists(szFileName))
	{
		FILE* fp = NULL;
		int err = _wfopen_s(&fp, szFileName, _T("r"));

		if (!err)
		{
			OutputDebugString(szFileName);
			_ftscanf_s(fp, _T("%s"), szIPAddress);
		}

		fclose(fp);

		GetEnvironmentVariable(VARNAME, szIPAddress, MAX_IPV4);
		TCHAR* szEnv = GetEnvironmentStrings();
		OutputDebugString(szEnv);
		OutputDebugString(_T("szIPAddress"));
		OutputDebugString(szIPAddress);
	}

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	//DestroyEnvironmentBlock(lpEnvironment);
	CoTaskMemFree(szPath);
	delete[] pszOldVal;
}
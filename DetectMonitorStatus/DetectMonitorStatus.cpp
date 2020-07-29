// DetectMonitorStatus.cpp : Implementation of WinMain
//////////////////////////////////////////////////////////////////////////////////////////////
// Product Name: Detect Monitor Status
// Developed By: N Kamleshwar Rao
// Dated Created: 19th July 2020
// Last Modified: 29th July 2020
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
#include <wincred.h>

#define RECYCLE_PERIOD		-10000000LL * 60 * 5
#define RECYCLE_TIMER		_T ( "Recycle Timer" )
#define PATH_SIZE			4096
#define MAX_IPV4			16
#define BUFSIZE				4096
#define VARNAME				_T ( "data" )
#define STACKSIZE			(5*1024)


TCHAR szFileName[MAX_PATH] = { 0 };
HANDLE hTimer = NULL;
LARGE_INTEGER liDueTime = { 0 } ;

HANDLE hDisplayTimerThread = NULL;
HANDLE hDisplayOffHandler = NULL;
using namespace ATL;

SERVICE_STATUS_HANDLE hService = NULL;
HDEVNOTIFY hDevNotify = NULL;
HPOWERNOTIFY hPwrNotify = NULL;

#include <stdio.h>

DWORD WINAPI DisplayTimerThread(LPVOID pData);
DWORD WINAPI DisplayOffHandler(LPVOID pData);
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
	void OnStop() throw()
	{
		OutputDebugString(_T("Stopping the Service."));
		SetServiceStatus(SERVICE_STOP_PENDING);
		UnregisterDeviceNotification(hDevNotify);
		UnregisterPowerSettingNotification(hPwrNotify);
		CloseHandle(hService);
		CloseHandle(hPwrNotify);

		__super::OnStop();
	}
	HRESULT Start(_In_ int nShowCmd) throw()
	{
		DWORD dwThreadId = 0;
		OutputDebugString(_T("Display Timer Thread Created in Suspended Mode"));
		hDisplayTimerThread = CreateThread(NULL, STACKSIZE, DisplayTimerThread, NULL, CREATE_SUSPENDED, &dwThreadId);

		return __super::Start(nShowCmd);
	}
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

						DWORD dwThreadId = 0;
						OutputDebugString(_T("Display Timer Thread Created in Suspended Mode"));
						hDisplayOffHandler = CreateThread(NULL, STACKSIZE, DisplayOffHandler, NULL, 0, &dwThreadId);
					}
					else if ((BYTE)pws->Data[0] == 1)
					{
						OutputDebugString(_T("Display Turned On"));
						//CancelWaitableTimer(hTimer);

						//Write Wake up Logic
						if (_tcslen(szFileName) && PathFileExists(szFileName))
						{
							//if (DeleteFile(szFileName))
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
						//SetEvent(hDisplayOffEvent);
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
						//CancelWaitableTimer(hTimer);

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
	//hDisplayOffEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	//hTerminateEvent = CreateEvent(NULL, TRUE, FALSE, NULL);


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
	OutputDebugString(_T("Resuming Display Timer Thread"));
	ResumeThread(hDisplayTimerThread);

	__super::ServiceMain(dwArgc, lpszArgv);
}


void CDetectMonitorStatusModule::Handler(DWORD dwOpcode)
{
	// TODO: Add your specialized code here and/or call the base class
	OutputDebugString(_T("Unable to Register the SystemNotificationHandler"));
	__super::Handler(dwOpcode);
}

HRESULT CDetectMonitorStatusModule::Run(int nShowCmd)
{
	return __super::Run(0);
}

DWORD WINAPI DisplayTimerThread(LPVOID pData)
{
	OutputDebugString(_T("DisplayTimerThread up and running"));

	hService = RegisterServiceCtrlHandlerEx(_T("DetectMonitorStatus"), SystemNotificationHandler, (LPVOID)NULL); //lpContext to receive the Data to process
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


	//Register Power Setting Notification Infrastructure
	//  The Windows Service needs to register for power events of system state transitioning.
	LPCGUID PowerSettingGuid = &GUID_CONSOLE_DISPLAY_STATE;
	hPwrNotify = RegisterPowerSettingNotification(hService, PowerSettingGuid, DEVICE_NOTIFY_SERVICE_HANDLE);
	if (hPwrNotify == NULL) {
		OutputDebugString(_T("Unable to Register the Power Setting Notification"));
		return 1;
	}

	return 0;
}

DWORD WINAPI DisplayOffHandler(LPVOID pData)
{
	SYSTEMTIME st;
	GetLocalTime(&st);

	std::string fmtStr;
	TCHAR szTimeStamp[MAX_PATH] = { 0 };
	swprintf_s(szTimeStamp, MAX_PATH, _T("%.2d/%.2d/%.2d %.2d:%.2d:%.2d"), st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);

	TCHAR szComputerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
	DWORD dwSize = (MAX_COMPUTERNAME_LENGTH + 1);
	GetComputerName(szComputerName, &dwSize);

	TCHAR szFileName[MAX_PATH] = { 0 };
	PWSTR szPath = NULL;
	HANDLE hToken = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	HRESULT hRes = SHGetKnownFolderPath(FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, hToken, &szPath);

	if (SUCCEEDED(hRes))
	{
		TCHAR szIPAddress[MAX_IPV4] = { 0 };
		GetPublicIPAddress(szIPAddress);

		_tcscpy_s(szFileName, MAX_PATH, (TCHAR*)szPath);

		PathAppend(szFileName, _T("Kiewit\\Kiewit.txt"));

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

		if (NULL != fp)
			fclose(fp);

		CoTaskMemFree(szPath);
	}

	return 0;
}

void GetPublicIPAddress(TCHAR* szIPAddress)
{
	TCHAR szFileName[MAX_PATH] = { 0 };
	PWSTR szPath = NULL; 
	HANDLE hToken = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	HRESULT hRes = SHGetKnownFolderPath(FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, hToken, &szPath);

	if (SUCCEEDED(hRes))
	{
		PathAppend(szPath, _T("Kiewit"));
		_tcscpy_s(szFileName, MAX_PATH, szPath);
		
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
			_ftprintf_s(fp, _T("@echo off\ncd \"%s\"\nnslookup myip.opendns.com resolver1.opendns.com > publicip.txt\nFIND \"Address\" publicip.txt > \"OnlyIP.txt\"\ndel publicip.txt\nFor /F \"skip=3 delims=\" %%%%i in (OnlyIP.txt) do set data=\"%%%%i\"\ndel OnlyIP.txt\nFor /f \"tokens=1,2 delims=:\" %%%%a IN (\"%%data%%\") do set data=%%%%b\nset data=%%data:~1,-1%%\necho %%data%% > IP.txt\n"), szPath);
		}

		fclose(fp);
	}

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	DWORD dwErr = 0;
	TCHAR szCmd[] = _T("C:\\Windows\\system32\\cmd.exe");

	hToken = NULL;
	TCHAR szCmdLine[MAX_PATH] = { _T("/C ") };
	TCHAR szFileNameWithQuotes[MAX_PATH] = { _T("") };
	swprintf_s(szFileNameWithQuotes, MAX_PATH, _T("\"%s\""), szFileName);
	_tcscat_s(szCmdLine, MAX_PATH, szFileNameWithQuotes );
			
	if (!CreateProcess(
		szCmd,   // No module name (use command line)
		szCmdLine,        // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		CREATE_UNICODE_ENVIRONMENT,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&si,            // Pointer to STARTUPINFO structure
		&pi)           // Pointer to PROCESS_INFORMATION structure
		)
	{
		printf("CreateProcess failed (%d).\n", GetLastError());
		dwErr = GetLastError();
		return;
	}
	else
		dwErr = GetLastError();


	WaitForSingleObject(pi.hProcess, INFINITE);


	_tcscpy_s(szFileName, MAX_PATH, szPath);

	PathAppend(szFileName, _T("IP.txt"));
	if (PathFileExists(szFileName))
	{
		FILE* fp = NULL;
		int err = _wfopen_s(&fp, szFileName, _T("r"));

		if (!err)
		{
			OutputDebugString(szFileName);
			fgetws(szIPAddress, MAX_IPV4, fp);
		}

		fclose(fp);

		OutputDebugString(_T("szIPAddress"));
		OutputDebugString(szIPAddress);
	}

	// Close process and thread handles. 
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	DeleteFile(szFileName); //IP.txt

	CoTaskMemFree(szPath);
}
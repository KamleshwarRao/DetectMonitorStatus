// DetectMonitorStatus.cpp : Implementation of WinMain


#include "pch.h"
#include "framework.h"
#include "resource.h"
#include "DetectMonitorStatus_i.h"


using namespace ATL;

#include <stdio.h>

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
	void ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv);
	void Handler(DWORD dwOpcode);
};

CDetectMonitorStatusModule _AtlModule;



//
extern "C" int WINAPI _tWinMain(HINSTANCE /*hInstance*/, HINSTANCE /*hPrevInstance*/,
								LPTSTR /*lpCmdLine*/, int nShowCmd)
{
	return _AtlModule.WinMain(nShowCmd);
}



void CDetectMonitorStatusModule::ServiceMain(DWORD dwArgc, LPTSTR* lpszArgv)
{
	// TODO: Add your specialized code here and/or call the base class
	__super::ServiceMain(dwArgc, lpszArgv);
}


void CDetectMonitorStatusModule::Handler(DWORD dwOpcode)
{
	// TODO: Add your specialized code here and/or call the base class
	__super::Handler(dwOpcode);
}

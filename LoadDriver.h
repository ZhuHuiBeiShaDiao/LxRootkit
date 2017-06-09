/******************************************************************************
**
**  FileName    :   LoadDriver.h
**  Version     :   0.10
**  Author      :   embedlinux(E-mai:hqulyc@126.com QQ:5054-3533)
**  Date        :   2008-08-04
**  Comment     :   加载内核级ROOTKIT
**
******************************************************************************/

#ifndef __LOAD_DRIVER_H__
#define __LOAD_DRIVER_H__

BOOL  SCMLoadDeviceDriver(PCHAR DrvFullPathName, //驱动程序完整路径名称
                          PCHAR DriverName); //name of service  LPCTSTR DriverName
DWORD SCMUnloadDeviceDriver(PCHAR DriverName);//Name of service
BOOL  LoadDeviceDriver(PCHAR DrvFullPathName, //注册表中驱动程序名称
				      PCHAR szDrvName); //驱动程序路径名称
BOOL  SystemLoadDeviceDriver();

#endif  //__LOAD_DRIVER_H__
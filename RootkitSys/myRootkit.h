//���Ͷ���

typedef ULONG DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;

//�ṹ����
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        struct {
            ULONG TimeDateStamp;
        };
        struct {
            PVOID LoadedImports;
        };
    };
    struct _ACTIVATION_CONTEXT * EntryPointActivationContext;

    PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _OBJECT_HEADER_CREATOR_INFO {
    LIST_ENTRY TypeList;
    HANDLE CreatorUniqueProcess;
    USHORT CreatorBackTraceIndex;
    USHORT Reserved;
} OBJECT_HEADER_CREATOR_INFO, *POBJECT_HEADER_CREATOR_INFO;

typedef struct _OBJECT_HEADER_NAME_INFO {
    PVOID Directory;
    UNICODE_STRING Name;
    ULONG QueryReferences;
} OBJECT_HEADER_NAME_INFO, *POBJECT_HEADER_NAME_INFO;

typedef struct _OBJECT_DIRECTORY_ENTRY {
    struct _OBJECT_DIRECTORY_ENTRY *ChainLink;
    PVOID Object;
    ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, *POBJECT_DIRECTORY_ENTRY;
//��������
ULONG g_uCr0;

extern POBJECT_TYPE NTSYSAPI PsProcessType;
extern POBJECT_TYPE NTSYSAPI PsThreadType;
_inline void WPOFF()
{
	
    ULONG uAttr;
	
    _asm
    {
        cli
		push eax
        mov eax, cr0
        mov g_uCr0, eax
        and eax, 0FFFEFFFFh // CR0 16 BIT = 0
        mov cr0, eax
        pop eax
        
    };
	
}

_inline void WPON()
{
	
    _asm
    {
        
		push eax
        mov eax, g_uCr0 //�֏�ԭ�� CR0 ����
        mov cr0, eax
        pop eax
		sti
    };
	
}

//һЩ����������

NTSYSAPI
NTSTATUS
NTAPI
NtDeviceIoControlFile (
			HANDLE FileHandle,
			HANDLE Event,
			PIO_APC_ROUTINE ApcRoutine,
			PVOID ApcContext,
			PIO_STATUS_BLOCK IoStatusBlock,
			ULONG IoControlCode,
			PVOID InputBuffer,
			ULONG InputBufferLength,
			PVOID OutputBuffer,
			ULONG OutputBufferLength
    );

NTSYSAPI
NTSTATUS
NTAPI
NtFsControlFile(
		HANDLE FileHandle,
		HANDLE Event,
		PIO_APC_ROUTINE ApcRoutine,
		PVOID ApcContext,
		PIO_STATUS_BLOCK IoStatusBlock,
		ULONG IoControlCode,
		PVOID InputBuffer,
		ULONG InputBufferLength,
		PVOID OutputBuffer,
		ULONG OutputBufferLength
    );

//һЩ����������
NTSYSAPI
NTSTATUS
NTAPI
NtWriteFile (
	IN HANDLE FileHandle,
	IN HANDLE Event,
	IN PIO_APC_ROUTINE ApcRoutine,
	IN PVOID ApcContext,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN PULONG Key
    );

NTSYSAPI
NTSTATUS
NTAPI
ObOpenObjectByName (
	POBJECT_ATTRIBUTES ObjectAttributes,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	PVOID ParseContext,
	PHANDLE Handle
    );
    
NTSYSAPI
UCHAR *
NTAPI
PsGetProcessImageFileName(
		PEPROCESS Process
    );
    
NTKERNELAPI
VOID
KeAttachProcess (
    IN PEPROCESS Process
);

NTKERNELAPI
VOID
KeDetachProcess (
    VOID
);
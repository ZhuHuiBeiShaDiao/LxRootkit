#ifndef __HOOKSYSCALL_H__
#define __HOOKSYSCALL_H__

#include "ntddk.h"
#include "windef.h"    //Windows Data Types
#include "ntimage.h"   //PE文件相关结构体
//#include "IrpFile.h"

#pragma pack(push, 1)
typedef struct _ServiceDescriptorTableEntry {
   unsigned int  *ServiceTableBase;        //array of entry points
   unsigned int  *ServiceCounterTableBase; //array of usage counters
   unsigned int  NumberOfServices;         //number of table entries
   unsigned char *ParamTableBase;          //array of byte counts
} ServiceDescriptorTableEntry, *PServiceDescriptorTableEntry;
#pragma pack(pop)
__declspec(dllimport) ServiceDescriptorTableEntry KeServiceDescriptorTable;


typedef enum _SYSTEM_INFORMATION_CLASS {
	 SystemBasicInformation = 0,					// 0	Y	N
	 SystemProcessorInformation,				// 1	Y	N
   SystemPerformanceInformation,			// 2	Y	N
	 SystemTimeOfDayInformation,				// 3	Y	N
	 SystemNotImplemented1,					// 4	Y	N	// SystemPathInformation
	 SystemProcessesAndThreadsInformation = 5,	// 5	Y	N
	 SystemCallCounts,						// 6	Y	N
	 SystemConfigurationInformation,			// 7	Y	N
	 SystemProcessorTimes,					// 8	Y	N
	 SystemGlobalFlag,						// 9	Y	Y
	 SystemNotImplemented2,					// 10	Y	N	// SystemCallTimeInformation
	 SystemModuleInformation,				// 11	Y	N
	 SystemLockInformation,					// 12	Y	N
	 SystemNotImplemented3,					// 13	Y	N	// SystemStackTraceInformation
	 SystemNotImplemented4,					// 14	Y	N	// SystemPagedPoolInformation
	 SystemNotImplemented5,					// 15	Y	N	// SystemNonPagedPoolInformation
	 SystemHandleInformation,				// 16	Y	N
	 SystemObjectInformation,				// 17	Y	N
	 SystemPagefileInformation,				// 18	Y	N
	 SystemInstructionEmulationCounts,		// 19	Y	N
	 SystemInvalidInfoClass1,				// 20
	 SystemCacheInformation,					// 21	Y	Y
	 SystemPoolTagInformation,				// 22	Y	N
	 SystemProcessorStatistics,				// 23	Y	N
	 SystemDpcInformation,					// 24	Y	Y
	 SystemNotImplemented6,					// 25	Y	N	// SystemFullMemoryInformation
	 SystemLoadImage,						// 26	N	Y	// SystemLoadGdiDriverInformation
	 SystemUnloadImage,						// 27	N	Y
	 SystemTimeAdjustment,					// 28	Y	Y
	 SystemNotImplemented7,					// 29	Y	N	// SystemSummaryMemoryInformation
	 SystemNotImplemented8,					// 30	Y	N	// SystemNextEventIdInformation
	 SystemNotImplemented9,					// 31	Y	N	// SystemEventIdsInformation
	 SystemCrashDumpInformation,				// 32	Y	N
	 SystemExceptionInformation,				// 33	Y	N
	 SystemCrashDumpStateInformation,		// 34	Y	Y/N
	 SystemKernelDebuggerInformation,		// 35	Y	N
	 SystemContextSwitchInformation,			// 36	Y	N
	 SystemRegistryQuotaInformation,			// 37	Y	Y
	 SystemLoadAndCallImage = 38,					// 38	N	Y	// SystemExtendServiceTableInformation
	 SystemPrioritySeparation,				// 39	N	Y
	 SystemNotImplemented10,					// 40	Y	N	// SystemPlugPlayBusInformation
	 SystemNotImplemented11,					// 41	Y	N	// SystemDockInformation
	 SystemInvalidInfoClass2,				// 42			// SystemPowerInformation
	 SystemInvalidInfoClass3,				// 43			// SystemProcessorSpeedInformation
	 SystemTimeZoneInformation,				// 44	Y	N
	 SystemLookasideInformation,				// 45	Y	N
	 SystemSetTimeSlipEvent,					// 46	N	Y
	 SystemCreateSession,					// 47	N	Y
	 SystemDeleteSession,					// 48	N	Y
	 SystemInvalidInfoClass4,				// 49
	 SystemRangeStartInformation,			// 50	Y	N
	 SystemVerifierInformation,				// 51	Y	Y
	 SystemAddVerifier,						// 52	N	Y
	 SystemSessionProcessesInformation		// 53	Y	N
} SYSTEM_INFORMATION_CLASS;

/************************从内核中恢复SSDT涉及的结构*********************/
#define SystemModuleInformation  11

//系统模块信息
typedef struct _SYSTEM_MODULE_INFORMATION {
   ULONG Reserved[2];
   PVOID Base; //The base address of the module.
   ULONG Size; //The size of the module.
   ULONG Flags;
   USHORT Index;
   USHORT Unknown;
   USHORT LoadCount;
   USHORT ModuleNameOffset;
   CHAR ImageName[256];//The filepath of the module.
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _MODULES {
   ULONG    NumberOfModules; //模块个数
   SYSTEM_MODULE_INFORMATION  smi;
} MODULES, *PMODULES;

typedef struct _NEED_INFO {
   ULONG    ImageBase;
   UCHAR    UseLess1[204];
   ULONG    VOffset;
   ULONG    UseLess2;
   ULONG    ROffset;
} NEED_INFO, *PNEED_INFO;

typedef struct _MODULE_LIST {
   ULONG    NumberOfModules;
   SYSTEM_MODULE_INFORMATION  SysModuleInfo[];
} MODULE_LIST, *PMODULE_LIST;

/**********************************************************************/
NTSTATUS NTAPI ZwQuerySystemInformation(
   IN ULONG SystemInformationClass,  //被查询的系统信息类型
   IN OUT PVOID SystemInformation,   //指向一个接受系统信息的缓冲区的指针
   IN ULONG SystemInformationLength, //缓冲区长度
   OUT PULONG ReturnLength           //指向一个接受实际返回字节数的变量,可以为0
);

typedef enum _OBJECT_INFORMATION_CLASS {
   ObjectBasicInformation = 0,
   ObjectNameInformation = 1,
   ObjectTypeInformation = 2,
} OBJECT_INFORMATION_CLASS;

NTSTATUS ZwQueryObject(
   IN HANDLE   OPTIONAL,
   IN OBJECT_INFORMATION_CLASS,
   OUT PVOID   OPTIONAL,
   IN ULONG,
   OUT PULONG   OPTIONAL
);

NTSTATUS ZwDuplicateObject(
   HANDLE SourceProcessHandle,
   HANDLE SourceHandle,
   HANDLE TargetProcessHandle,
   PHANDLE TargetHandle,
   ACCESS_MASK DesiredAccess,
   ULONG Attributes,
   ULONG Options
);

NTSYSAPI NTSTATUS NTAPI ZwOpenProcess (
   OUT PHANDLE ProcessHandle,
   IN ACCESS_MASK DesiredAccess, 
   IN POBJECT_ATTRIBUTES ObjectAttributes,
   IN PCLIENT_ID ClientId 
);

NTSYSAPI NTSTATUS NTAPI ZwTerminateProcess(
   IN HANDLE ProcessHandle,
   IN NTSTATUS ExitStatus
);

NTSYSAPI NTSTATUS NTAPI ZwSaveKey(
   IN HANDLE KeyHandle,
   IN HANDLE FileHandle 
);

NTSYSAPI NTSTATUS NTAPI ZwLoadDriver(
   IN PUNICODE_STRING DriverServiceName
);

#endif //_HOOKSYSCALL_H_
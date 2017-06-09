typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle; 
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList; 
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA,*PPEB_LDR_DATA; 
/*
lkd> dt _CONTROL_AREA
nt!_CONTROL_AREA
+0x000 Segment          : Ptr32 _SEGMENT
+0x004 DereferenceList  : _LIST_ENTRY
+0x00c NumberOfSectionReferences : Uint4B
+0x010 NumberOfPfnReferences : Uint4B
+0x014 NumberOfMappedViews : Uint4B
+0x018 NumberOfSubsections : Uint2B
+0x01a FlushInProgressCount : Uint2B
+0x01c NumberOfUserReferences : Uint4B
+0x020 u                : __unnamed
+0x024 FilePointer      : Ptr32 _FILE_OBJECT
+0x028 WaitingForDeletion : Ptr32 _EVENT_COUNTER
+0x02c ModifiedWriteCount : Uint2B
+0x02e NumberOfSystemCacheViews : Uint2B
*/
typedef struct _CONTROL_AREA {
	//CONTROL_AREA Strutct for winxp
    PVOID Segment; //PSEGMENT
    LIST_ENTRY DereferenceList;
    ULONG NumberOfSectionReferences;    // All section refs & image flushes
    ULONG NumberOfPfnReferences;        // valid + transition prototype PTEs
    ULONG NumberOfMappedViews;          // total # mapped views, including
	// system cache & system space views
    USHORT NumberOfSubsections;     // system cache views only
	USHORT FlushInProgressCount;
    ULONG NumberOfUserReferences;       // user section & view references
    ULONG LongFlags;
    PFILE_OBJECT FilePointer;
    PVOID WaitingForDeletion; //PEVENT_COUNTER
    USHORT ModifiedWriteCount;
    USHORT NumberOfSystemCacheViews;
} CONTROL_AREA, *PCONTROL_AREA;


typedef struct _MMVAD {
	//MMVAD Struct for winxp
	ULONG_PTR StartingVpn;
    ULONG_PTR EndingVpn;
    struct _MMVAD *Parent;
	struct _MMVAD *LeftChild;
    struct _MMVAD *RightChild;
	ULONG_PTR LongFlags;
    PCONTROL_AREA ControlArea;
    PVOID FirstPrototypePte; //PMMPTE
    PVOID LastContiguousPte;//PMMPTE
    ULONG LongFlags2;
} MMVAD, *PMMVAD;
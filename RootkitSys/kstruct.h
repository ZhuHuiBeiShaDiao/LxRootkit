typedef struct _EPROCESS {
     KPROCESS                            Pcb; // +0x000
     EX_PUSH_LOCK                     ProcessLock; // +0x06c
     LARGE_INTEGER                   CreateTime; // +0x070
     LARGE_INTEGER                   ExitTime; // +0x078
     EX_RUNDOWN_REF                RundownProtect; // +0x080
     ULONG                                  UniqueProcessId; // +0x084
     LIST_ENTRY                          ActiveProcessLinks; // +0x088
     ULONG                                    QuotaUsage[3]; // +0x090
     ULONG                                   QuotaPeak[3]; // +0x09c
     ULONG                                   CommitCharge; // +0x0a8
     ULONG                                   PeakVirtualSize; // +0x0ac
     ULONG                                   VirtualSize; // +0x0b0
     LIST_ENTRY                          SessionProcessLinks; // +0x0b4
     PVOID                                    DebugPort; // +0x0bc
     PVOID                                   ExceptionPort; // +0x0c0
     PHANDLE_TABLE                   ObjectTable; // +0x0c4
     EX_FAST_REF                     Token; // +0x0c8
     FAST_MUTEX                        WorkingSetLock; // +0x0cc
    ULONG                                      WorkingSetPage; // +0x0ec
     KGUARDED_MUTEX               AddressCreationLock; // +0x0f0
     ULONG                                   HyperSpaceLock; // +0x110
     PETHREAD                           ForkInProgress; // +0x114
     ULONG                                HardwareTrigger; // +0x118
    PVOID                                     VadRoot;// +0x11c
    PVOID                                     VadHint;// +0x120
     PVOID                                 CloneRoot; // +0x124
     ULONG                                  NumberOfPrivatePages; // +0x128
     ULONG                                NumberOfLockedPages; // +0x12c
     PVOID                                   Win32Process; // +0x130
     PEJOB                                Job; // +0x134
     PVOID                                 SectionObject; // +0x138
     PVOID                                 SectionBaseAddress; // +0x13c
     PEPROCESS_QUOTA_BLOCK           QuotaBlock; // +0x140
     PPAGEFAULT_HISTORY                    WorkingSetWatch; // +0x144
     PVOID                           Win32WindowStation; // +0x148
     ULONG                           InheritedFromUniqueProcessId; // +0x14c
     PVOID                           LdtInformation; // +0x150
     PVOID                           VadFreeHint; // +0x154
     PVOID                           VdmObjects; // +0x158
     PVOID                           DeviceMap; // +0x15c
    LIST_ENTRY                  PhysicalVadList; //+0x160
     union {
         HARDWARE_PTE                PageDirectoryPte; // +0x168
         UINT64                      Filler; // +0x168
     };
     PVOID                           Session; // +0x170
     UCHAR                           ImageFileName[16]; // +0x174
     LIST_ENTRY                      JobLinks; // +0x184
     PVOID                           LockedPagesList; // +0x18c
     LIST_ENTRY                      ThreadListHead; // +0x190
     PVOID                           SecurityPort; // +0x198
     PVOID                           PaeTop; // +0x19c
     ULONG                           ActiveThreads; // +0x1a0
     ULONG                           GrantedAccess; // +0x1a4
     ULONG                           DefaultHardErrorProcessing; // +0x1a8
     SHORT                           LastThreadExitStatus; // +0x1ac
     PPEB                            Peb; // +0x1b0
     EX_FAST_REF                     PrefetchTrace; // +0x1b4
     LARGE_INTEGER                   ReadOperationCount; // +0x1b8
     LARGE_INTEGER                   WriteOperationCount; // +0x1c0
     LARGE_INTEGER                   OtherOperationCount; // +0x1c8
     LARGE_INTEGER                   ReadTransferCount; // +0x1d0
     LARGE_INTEGER                   WriteTransferCount; // +0x1d8
     LARGE_INTEGER                   OtherTransferCount; // +0x1e0
     ULONG                           CommitChargeLimit; // +0x1e8
     ULONG                           CommitChargePeak; // +0x1ec
     PVOID                           AweInfo; // +0x1f0
     SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo; // +0x1f4
     MMSUPPORT                       Vm; // +0x1f8
    ULONG                            LastFaultCount; // 0x238
     ULONG                           ModifiedPageCount; // +0x23c
     ULONG                          NumberOfVads; // 0x240
     ULONG                           JobStatus; // +0x244
     union {
         ULONG                       Flags; // 0x248
         struct {
             ULONG                   CreateReported              : 1;
             ULONG                   NoDebugInherit              : 1;
             ULONG                   ProcessExiting              : 1;
             ULONG                   ProcessDelete               : 1;
             ULONG                   Wow64SplitPages             : 1;
             ULONG                   VmDeleted                   : 1;
             ULONG                   OutswapEnabled              : 1;
             ULONG                   Outswapped                  : 1;
             ULONG                   ForkFailed                  : 1;
             ULONG                   Wow64VaSpace4Gb             : 1;
             ULONG                   AddressSpaceInitialized     : 2;
             ULONG                   SetTimerResolution          : 1;
             ULONG                   BreakOnTermination          : 1;
             ULONG                   SessionCreationUnderway     : 1;
             ULONG                   WriteWatch                  : 1;
             ULONG                   ProcessInSession            : 1;
             ULONG                   OverrideAddressSpace        : 1;
             ULONG                   HasAddressSpace             : 1;
             ULONG                   LaunchPrefetched            : 1;
             ULONG                   InjectInpageErrors          : 1;
             ULONG                   VmTopDown                   : 1;
             ULONG                   ImageNotifyDone             : 1;
             ULONG                   PdeUpdateNeeded             : 1;
             ULONG                   VdmAllowed                  : 1;
             ULONG                   Unused                      : 7;
         };
     };
     NTSTATUS                        ExitStatus; // +0x24c
     USHORT                          NextPageColor; // +0x250
     union {
         struct {
             UCHAR                   SubSystemMinorVersion; // +0x252
             UCHAR                   SubSystemMajorVersion; // +0x253
         };
         USHORT                      SubSystemVersion; // +0x252
     };
     UCHAR                           PriorityClass; // +0x254
 UCHAR        WorkingSetAcquiredUnsafe; // 0x255
 ULONG        Cookie; // +0x258
 } EPROCESS, *PEPROCESS;
 
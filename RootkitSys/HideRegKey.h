/******************************************************************************
**
**  FileName    :   HideRegKey.h
**  Version     :   0.10
**  Author      :   embedlinux(E-mai:hqulyc@126.com QQ:5054-3533)
**  Date        :   2008-08-04
**  Comment     :   
**
******************************************************************************/

#ifndef __HIDE_REGKEY_H__
#define __HIDE_REGKEY_H__

#include <ntddk.h>

#define  GET_PTR(ptr, offset) ( *(PVOID*)( (ULONG)ptr + (offset##Offset) ) )

#define  CM_KEY_INDEX_ROOT  0x6972  // ir
#define  CM_KEY_INDEX_LEAF  0x696c  // il
#define  CM_KEY_FAST_LEAF   0x666c  // fl
#define  CM_KEY_HASH_LEAF   0x686c  // hl


//һЩCM�����ݽṹ��ֻ�г��õ��Ŀ�ͷ����
#pragma pack(push, 1)
typedef struct _CM_KEY_NODE { //ע���ڵ�
   USHORT Signature;
   USHORT Flags;
   LARGE_INTEGER LastWriteTime;
   ULONG Spare;   //used to be TitleIndex
   HANDLE Parent; //���ڵ�
   ULONG SubKeyCounts[2]; //Stable and Volatile
   HANDLE SubKeyLists[2]; //Stable and Volatile
   // ...
} CM_KEY_NODE, *PCM_KEY_NODE;

typedef struct _CM_KEY_INDEX {//ע�������
   USHORT Signature;
   USHORT Count;
   HANDLE List[1];
} CM_KEY_INDEX, *PCM_KEY_INDEX;

//������ṹ
typedef struct _CM_KEY_BODY {
   ULONG Type;             // "ky02"
   PVOID KeyControlBlock;
   PVOID NotifyBlock;
   PEPROCESS Process;      //the owner process
   LIST_ENTRY KeyBodyList; //key_nodes using the same kcb
} CM_KEY_BODY, *PCM_KEY_BODY;

typedef PVOID (__stdcall *PGET_CELL_ROUTINE)(
   PVOID, 
   HANDLE
);
typedef struct _HHIVE {
   ULONG Signature;
   PGET_CELL_ROUTINE GetCellRoutine;
   // ...
} HHIVE, *PHHIVE;
#pragma pack(pop)


VOID     UnHideRegKey();                   //Unload�����е���
NTSTATUS HideRegKey(IN PWCHAR HideKeyName);//DriverEntry�е���

#endif  //_HIDEREGKEY_H_
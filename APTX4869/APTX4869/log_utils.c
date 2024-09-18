#include "log_utils.h"
#include <stdarg.h>
#include <wchar.h>
#include <ntstrsafe.h>

#define LOG_FILE_PATH L"\\SystemRoot\\System32\\drivers\\APTX4869_logs.txt"

#define BUFFER_SIZE 1024

static HANDLE logFileHandle = NULL;

VOID 
InitializeLogFile(VOID) {
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING fileName;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    RtlInitUnicodeString(&fileName, LOG_FILE_PATH);
    InitializeObjectAttributes(&objAttr, &fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    status = ZwCreateFile(&logFileHandle, GENERIC_WRITE | SYNCHRONIZE, &objAttr, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[-] Failed to create or open log file. Status: 0x%X\n", status));
    }
}

VOID 
LogMessage(const char* format, ...) {
    if (logFileHandle == NULL) {
        InitializeLogFile();
    }

    if (logFileHandle == NULL) {
        return;
    }

    va_list args;
    WCHAR wideBuffer[BUFFER_SIZE];
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    UNICODE_STRING message;

    va_start(args, format);

    RtlStringCchPrintfW(wideBuffer, BUFFER_SIZE, L"%hs", format);

    va_end(args);

    RtlInitUnicodeString(&message, wideBuffer);

    status = ZwWriteFile(logFileHandle, NULL, NULL, NULL, &ioStatus, message.Buffer, message.Length, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[-] Failed to write to log file. Status: 0x%X\n", status));
    }
}

VOID 
CloseLogFile(VOID) {
    if (logFileHandle != NULL) {
        ZwClose(logFileHandle);
        logFileHandle = NULL;
    }
}

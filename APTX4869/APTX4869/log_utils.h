#pragma once
#ifndef _LOG_UTILS_H_
#define _LOG_UTILS_H_

#include <ntddk.h>

VOID InitializeLogFile(VOID);
VOID LogMessage(const char* format, ...);
VOID CloseLogFile(VOID);

#endif

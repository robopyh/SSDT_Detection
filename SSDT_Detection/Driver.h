#pragma once
#include <ntifs.h>
#include <wdf.h>

typedef struct SystemServiceDescriptorTable
{
	PULONG ServiceTableBase;
	PULONG ServiceCounterTableBase;
	ULONG NumberOfServices;
	PUCHAR ParamTableBase;
}SSDT, *PSSDT;

extern PSSDT KeServiceDescriptorTable; //pointer to the SSDT

typedef enum tagSYSTEM_INFORMATION_CLASS {
	SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

NTKERNELAPI
NTSTATUS
ZwQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
	ULONG  Unknown1;
	ULONG  Unknown2;
	ULONG  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT  Index;
	USHORT  NameLength;
	USHORT  LoadCount;
	USHORT  PathLength;
	CHAR  ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
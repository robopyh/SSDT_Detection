#include "Driver.h"
#include <ntstrsafe.h>

EVT_WDF_DRIVER_UNLOAD DriverUnload;



NTSTATUS GetKernelRange(PCHAR moduleName, SYSTEM_MODULE_INFORMATION_ENTRY* module) {
	NTSTATUS status;
	ULONG    systemInfoBufferSize = 0;
	PSYSTEM_MODULE_INFORMATION systemModuleInfo = NULL;

	status = ZwQuerySystemInformation(SystemModuleInformation, &systemInfoBufferSize, 0, &systemInfoBufferSize);

	systemModuleInfo = (PSYSTEM_MODULE_INFORMATION) ExAllocatePool(NonPagedPool, systemInfoBufferSize);

	status = ZwQuerySystemInformation(SystemModuleInformation, systemModuleInfo, systemInfoBufferSize, &systemInfoBufferSize);

	for (ULONG i = 0; i < systemModuleInfo->Count; i++) {
		if (!_stricmp(systemModuleInfo->Module[i].ImageName + systemModuleInfo->Module[i].PathLength, moduleName)) {
			*module = systemModuleInfo->Module[i];
			return STATUS_SUCCESS;
		}
	}
	return STATUS_FAILED_DRIVER_ENTRY; 
}

BOOLEAN IsAddressOutOfKernel(SYSTEM_MODULE_INFORMATION_ENTRY module, ULONG address) {
	if (address < module.Base || address > (module.Base + module.Size)) {
		return TRUE;
	}
	return FALSE;
}

CHAR* GetHookModule(ULONG address) {
	NTSTATUS status;
	ULONG    systemInfoBufferSize = 0;
	PSYSTEM_MODULE_INFORMATION systemModuleInfo = NULL;


	status = ZwQuerySystemInformation(SystemModuleInformation, &systemInfoBufferSize, 0, &systemInfoBufferSize);

	systemModuleInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, systemInfoBufferSize);

	status = ZwQuerySystemInformation(SystemModuleInformation, systemModuleInfo, systemInfoBufferSize, &systemInfoBufferSize);

	for (ULONG i = 0; i < systemModuleInfo->Count; i++) {
		if (address >= systemModuleInfo->Module[i].Base && address <= (systemModuleInfo->Module[i].Base + systemModuleInfo->Module[i].Size)) {
			return (systemModuleInfo->Module[i].ImageName + systemModuleInfo->Module[i].PathLength);
		}
	}
	return "";
}

VOID ScanSSDTHook() {
	SYSTEM_MODULE_INFORMATION_ENTRY module;
	
	GetKernelRange("ntkrnlpa.exe", &module);

	for (ULONG i = 0; i < KeServiceDescriptorTable->NumberOfServices; i++) {
		if (IsAddressOutOfKernel(module, KeServiceDescriptorTable->ServiceTableBase[i])) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Syscall #%d at %08lX is hooked!\n", i, KeServiceDescriptorTable->ServiceTableBase[i]);
			CHAR* ImageFile = GetHookModule(KeServiceDescriptorTable->ServiceTableBase[i]);
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Hook module: %s!\n", ImageFile);
			return;
		}
	}

}

//Driver entry point
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath) {

	NTSTATUS status;
	WDF_DRIVER_CONFIG config;

	WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);

	config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
	config.EvtDriverUnload = DriverUnload;

	ScanSSDTHook();

	status = WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);

	return status;
}

VOID DriverUnload(_In_ WDFDRIVER Driver) {
	UNREFERENCED_PARAMETER(Driver);
	PAGED_CODE();
	return;
};
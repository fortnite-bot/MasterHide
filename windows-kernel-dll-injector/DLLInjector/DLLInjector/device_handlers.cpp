#include "device_handlers.h"

#include "common.h"
#include "Injector.h"

static NTSTATUS InitDllPathFromArgs(const InjectDllArgs* args, PUNICODE_STRING dll_path) {
	if (nullptr == args || nullptr == dll_path) {
		return STATUS_INVALID_PARAMETER;
	}

	size_t length = 0;
	while (length < RTL_NUMBER_OF(args->dll_path) && L'\0' != args->dll_path[length]) {
		length++;
	}

	if (0 == length || length == RTL_NUMBER_OF(args->dll_path)) {
		return STATUS_INVALID_PARAMETER;
	}

	dll_path->Buffer = const_cast<PWCH>(args->dll_path);
	dll_path->Length = static_cast<USHORT>(length * sizeof(WCHAR));
	dll_path->MaximumLength = sizeof(args->dll_path);
	return STATUS_SUCCESS;
}

NTSTATUS device_create_close(PDEVICE_OBJECT device_object, PIRP irp) {
	UNREFERENCED_PARAMETER(device_object);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS device_ioctl(PDEVICE_OBJECT device_object, PIRP irp) {
	UNREFERENCED_PARAMETER(device_object);

	NTSTATUS nt_status;
	PIO_STACK_LOCATION  irp_stack_location = IoGetCurrentIrpStackLocation(irp);
	size_t input_buffer_length = irp_stack_location->Parameters.DeviceIoControl.InputBufferLength;

	switch (irp_stack_location->Parameters.DeviceIoControl.IoControlCode) {
	case INJECT_DLL_IOCTL:
	{
		if (input_buffer_length != sizeof InjectDllArgs) {
			nt_status = STATUS_INVALID_PARAMETER;
			break;
		}
		auto args = static_cast<InjectDllArgs*>(irp->AssociatedIrp.SystemBuffer);
		UNICODE_STRING dll_path = {};
		nt_status = InitDllPathFromArgs(args, &dll_path);
		if (!NT_SUCCESS(nt_status)) {
			break;
		}
		nt_status = InjectDllIntoProcess(reinterpret_cast<HANDLE>(args->pid), &dll_path);
	}
	break;
	default: 
	{
		nt_status = STATUS_INVALID_DEVICE_REQUEST;
	}
	break;
	}

	irp->IoStatus.Status = nt_status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return nt_status;
}

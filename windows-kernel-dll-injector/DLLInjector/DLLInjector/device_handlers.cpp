#include "device_handlers.h"

#include "common.h"
#include "diag.h"
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
	size_t output_buffer_length = irp_stack_location->Parameters.DeviceIoControl.OutputBufferLength;

	irp->IoStatus.Information = 0;

	switch (irp_stack_location->Parameters.DeviceIoControl.IoControlCode) {
	case INJECT_DLL_IOCTL:
	{
		if (input_buffer_length != sizeof InjectDllArgs) {
			DiagReset(0);
			DiagSetOverallStatus(STATUS_INVALID_PARAMETER);
			nt_status = STATUS_INVALID_PARAMETER;
			break;
		}
		auto args = static_cast<InjectDllArgs*>(irp->AssociatedIrp.SystemBuffer);
		DiagReset(static_cast<unsigned long long>(args->pid));
		UNICODE_STRING dll_path = {};
		nt_status = InitDllPathFromArgs(args, &dll_path);
		if (!NT_SUCCESS(nt_status)) {
			DiagSetOverallStatus(nt_status);
			break;
		}
		DiagSetDllPathLength(dll_path.Length);
		DbgPrint("[INJDIAG] inject request pid=%p dll_len=0x%X\n", reinterpret_cast<HANDLE>(args->pid), dll_path.Length);
		nt_status = InjectDllIntoProcess(reinterpret_cast<HANDLE>(args->pid), &dll_path);
	}
	break;
	case GET_INJECT_DIAGNOSTIC_IOCTL:
	{
		if (output_buffer_length < sizeof(InjectionDiagnosticSnapshot)) {
			nt_status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		auto snapshot = static_cast<InjectionDiagnosticSnapshot*>(irp->AssociatedIrp.SystemBuffer);
		DiagCopy(snapshot);
		irp->IoStatus.Information = sizeof(InjectionDiagnosticSnapshot);
		nt_status = STATUS_SUCCESS;
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

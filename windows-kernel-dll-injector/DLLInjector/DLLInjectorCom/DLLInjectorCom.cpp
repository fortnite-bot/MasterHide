#include <Windows.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "../DLLInjector/common.h"

namespace {

std::wstring Hex32(long value) {
	std::wostringstream stream;
	stream << L"0x" << std::uppercase << std::hex << std::setw(8) << std::setfill(L'0')
		<< static_cast<unsigned long>(value);
	return stream.str();
}

std::wstring Hex64(unsigned long long value) {
	std::wostringstream stream;
	stream << L"0x" << std::uppercase << std::hex << std::setw(16) << std::setfill(L'0')
		<< value;
	return stream.str();
}

const wchar_t* StageName(unsigned long stage) {
	switch (stage) {
	case InjectionDiagnosticStageIdle:
		return L"idle";
	case InjectionDiagnosticStageIoctlReceived:
		return L"ioctl_received";
	case InjectionDiagnosticStageProcessLookup:
		return L"process_lookup";
	case InjectionDiagnosticStagePayloadCreation:
		return L"payload_creation";
	case InjectionDiagnosticStageThreadEnumeration:
		return L"thread_enumeration";
	case InjectionDiagnosticStageQueueApc:
		return L"queue_apc";
	case InjectionDiagnosticStageComplete:
		return L"complete";
	default:
		return L"unknown";
	}
}

void DumpSnapshot(std::wostream& output, const InjectionDiagnosticSnapshot& snapshot) {
	output << L"diag.version=" << snapshot.version << L"\n";
	output << L"diag.stage=" << StageName(snapshot.stage) << L" (" << snapshot.stage << L")\n";
	output << L"diag.pid=" << snapshot.pid << L"\n";
	output << L"diag.dll_path_length_bytes=" << snapshot.dll_path_length_bytes << L"\n";
	output << L"diag.overall_status=" << Hex32(snapshot.overall_status) << L"\n";
	output << L"diag.process_lookup_status=" << Hex32(snapshot.process_lookup_status) << L"\n";
	output << L"diag.load_library_status=" << Hex32(snapshot.load_library_status) << L"\n";
	output << L"diag.load_library_address=" << Hex64(snapshot.load_library_address) << L"\n";
	output << L"diag.context_alloc_status=" << Hex32(snapshot.context_alloc_status) << L"\n";
	output << L"diag.routine_alloc_status=" << Hex32(snapshot.routine_alloc_status) << L"\n";
	output << L"diag.apc_routine_size=" << snapshot.apc_routine_size << L"\n";
	output << L"diag.thread_enumeration_status=" << Hex32(snapshot.thread_enumeration_status) << L"\n";
	output << L"diag.enumerated_thread_count=" << snapshot.enumerated_thread_count << L"\n";
	output << L"diag.queued_apc_count=" << snapshot.queued_apc_count << L"\n";
	output << L"diag.first_queue_success_thread_id=" << snapshot.first_queue_success_thread_id << L"\n";
	output << L"diag.first_thread_lookup_failure_id=" << snapshot.first_thread_lookup_failure_id << L"\n";
	output << L"diag.first_thread_lookup_failure_status=" << Hex32(snapshot.first_thread_lookup_failure_status) << L"\n";
	output << L"diag.first_queue_failure_thread_id=" << snapshot.first_queue_failure_thread_id << L"\n";
	output << L"diag.first_queue_failure_status=" << Hex32(snapshot.first_queue_failure_status) << L"\n";
	output << L"diag.last_thread_id=" << snapshot.last_thread_id << L"\n";
	output << L"diag.last_thread_status=" << Hex32(snapshot.last_thread_status) << L"\n";
}

void PrintUsage() {
	std::wcerr << L"usage: DLLInjectorCom.exe <dll_path> <pid> [diag_output_path]\n";
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
	if (argc < 3 || argc > 4) {
		PrintUsage();
		return 1;
	}

	HANDLE driver = CreateFileW(L"\\\\.\\DLLInjector", GENERIC_READ | GENERIC_WRITE, 0,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (INVALID_HANDLE_VALUE == driver) {
		std::wcerr << L"CreateFileW failed: " << GetLastError() << L"\n";
		return 1;
	}

	InjectDllArgs args = {};
	wcsncpy_s(args.dll_path, argv[1], _TRUNCATE);
	args.pid = static_cast<size_t>(_wcstoui64(argv[2], nullptr, 0));

	DWORD bytes_returned = 0;
	BOOL inject_ok = DeviceIoControl(driver, INJECT_DLL_IOCTL, &args, sizeof(InjectDllArgs),
		nullptr, 0, &bytes_returned, nullptr);
	DWORD inject_error = inject_ok ? ERROR_SUCCESS : GetLastError();

	InjectionDiagnosticSnapshot snapshot = {};
	BOOL diag_ok = DeviceIoControl(driver, GET_INJECT_DIAGNOSTIC_IOCTL, nullptr, 0,
		&snapshot, sizeof(snapshot), &bytes_returned, nullptr);
	DWORD diag_error = diag_ok ? ERROR_SUCCESS : GetLastError();

	std::wostringstream report;
	report << L"inject.deviceiocontrol=" << (inject_ok ? L"success" : L"failure") << L"\n";
	report << L"inject.win32_error=" << inject_error << L"\n";
	report << L"diag.deviceiocontrol=" << (diag_ok ? L"success" : L"failure") << L"\n";
	report << L"diag.win32_error=" << diag_error << L"\n";
	if (diag_ok) {
		DumpSnapshot(report, snapshot);
	}

	std::wcout << report.str();
	if (4 == argc) {
		std::wofstream file(argv[3], std::ios::out | std::ios::trunc);
		if (file.is_open()) {
			file << report.str();
		}
	}

	CloseHandle(driver);
	return inject_ok ? 0 : 2;
}

#include "ProcessReference.h"

#define DLLINJECTOR_POOL_TAG 'jILD'

ProcessReference::ProcessReference()
	: m_process(nullptr) {
}

ProcessReference::~ProcessReference() {
	if (nullptr != m_process) {
		ObDereferenceObject(m_process);
		if (m_attach) {
			KeUnstackDetachProcess(m_apc_state);
			ExFreePool(m_apc_state);
		}
	}
	
}

NTSTATUS ProcessReference::init(size_t pid, bool attach) {
	CHECK(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(pid), &m_process));
	m_attach = attach;
	if (attach) {
		m_apc_state = (KAPC_STATE*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC_STATE), DLLINJECTOR_POOL_TAG);
		KeStackAttachProcess(m_process, m_apc_state);
	}
	return STATUS_SUCCESS;
}

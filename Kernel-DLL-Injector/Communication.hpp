#include "Operation.hpp"

class Communication
{
public:
	static OperationCallback Init(string moduleName, string exportName);
	
	static bool TestOperation(OperationCallback operation);

	static NTSTATUS CopyVirtualMemory(OperationCallback operation, ULONGLONG srcPid, uintptr_t srcAddr, ULONGLONG targetPid, uintptr_t targetAddr, SIZE_T size);
	static uint64_t GetModuleBaseOperation(OperationCallback operation, ULONGLONG processId, wstring moduleName);

	static uint64_t AllocateVirtualMemory(OperationCallback operation, ULONGLONG targetPid, size_t size, uint32_t allocationType, uint32_t protect, uintptr_t sourceAddress);
	static NTSTATUS ProtectVirtualMemory(OperationCallback operation, ULONGLONG targetPid, size_t size, uint32_t protect, uintptr_t sourceAddress);
	static NTSTATUS FreeVirtualMemory(OperationCallback operation, ULONGLONG targetPid, uintptr_t address);
};
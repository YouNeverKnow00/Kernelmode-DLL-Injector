#include "MemoryUtils.hpp"

MemoryUtils::MemoryUtils(OperationCallback operation, uint64_t pid)
{
	operationCallback = operation;
	processId = pid;
}

NTSTATUS MemoryUtils::ReadBuffer(uint64_t address, LPVOID lpBuffer, SIZE_T nSize)
{
	if (lpBuffer == 0)
		return STATUS_INVALID_PARAMETER;

	return Communication::CopyVirtualMemory(operationCallback, processId, address, GetCurrentProcessId(), uintptr_t(lpBuffer), nSize);
}

NTSTATUS MemoryUtils::WriteMemory(uint64_t address, uintptr_t dstAddress, SIZE_T nSize)
{
	if (dstAddress == 0)
		return STATUS_INVALID_PARAMETER;

	return Communication::CopyVirtualMemory(operationCallback, GetCurrentProcessId(), dstAddress, processId, address, nSize);
}

uint64_t MemoryUtils::ReadChain(uint64_t base, const std::vector<uint64_t>& offsets)
{
	uint64_t result = Read<uint64_t>(base + offsets.at(0));

	for (int i = 1; i < offsets.size(); i++)
		result = Read<uint64_t>(result + offsets.at(i));

	return result;
}

uint64_t MemoryUtils::GetModuleBase(wstring moduleName)
{
	return Communication::GetModuleBaseOperation(operationCallback, processId, moduleName);
}

string MemoryUtils::GetUnicodeString(uint64_t address, int strLength)
{
	char16_t wcharTmp[64] = { '\0' };
	ReadBuffer(address, wcharTmp, strLength * 2);

	std::string utfStr = std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t>{}.to_bytes(wcharTmp);

	return utfStr;
}

uint64_t MemoryUtils::AllocateMemory(size_t size, uint32_t allocation_type, uint32_t protect)
{
	uint64_t address = 0;
	return Communication::AllocateVirtualMemory(operationCallback, processId, size, allocation_type, protect, address);
}

NTSTATUS MemoryUtils::ProtectMemory(uint64_t address, size_t size, uint32_t protect)
{
	return Communication::ProtectVirtualMemory(operationCallback, processId, size, protect, address);
}

NTSTATUS MemoryUtils::FreeMemory(uint64_t address)
{
	return Communication::FreeVirtualMemory(operationCallback, processId, address);
}
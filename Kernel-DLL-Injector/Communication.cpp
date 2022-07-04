#include "Communication.hpp"

OperationCallback Communication::Init(string moduleName, string exportName)
{
	auto hModule = LoadLibraryA(moduleName.c_str());

	if (!hModule)
	{
		printf(xor ("[-] Communication init error: Failed to load library.\n"));
		return nullptr;
	}

	OperationCallback callback = (OperationCallback)GetProcAddress(hModule, exportName.c_str());

	if (!callback)
	{
		printf(xor ("[-] Communication init error: Export not found.\n"));
		return nullptr;
	}

	return callback;
}

bool Communication::TestOperation(OperationCallback operation)
{
	PACKET_BASE packet{};

	packet.op = TEST;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		printf(xor ("[+] Test operation failed.\n"));
		return false;
	}

	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	return packet.client.test.valid;
}

NTSTATUS Communication::CopyVirtualMemory(OperationCallback operation, ULONGLONG srcPid, uintptr_t srcAddr, ULONGLONG targetPid, uintptr_t targetAddr, SIZE_T size)
{
	PACKET_BASE packet{};

	packet.op = COPY_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	auto& serverRequest = packet.server.copy_virtual_memory;

	serverRequest.sourcePid = srcPid;
	serverRequest.sourceAddress = srcAddr;

	serverRequest.targetPid = targetPid;
	serverRequest.targetAddress = targetAddr;

	serverRequest.size = size;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		//printf(xor ("[+] Copy virtual memory operation failed.\n"));
		return STATUS_INVALID_HANDLE;
	}

	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	auto clientRequest = packet.client.copy_virtual_memory;

	return NTSTATUS(clientRequest.size);
}

uint64_t Communication::GetModuleBaseOperation(OperationCallback operation, ULONGLONG processId, wstring moduleName)
{
	PACKET_BASE packet{};

	packet.op = GET_MODULE_BASE_SIZE;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	auto& serverRequest = packet.server;
	moduleName.copy(serverRequest.get_module.name, moduleName.length());

	serverRequest.get_module.pid = processId;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		printf(xor ("[+] Get module base operation failed.\n"));
		return -1;
	}

	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	auto clientRequest = packet.client.get_module;

	return clientRequest.baseAddress;
}

uint64_t Communication::AllocateVirtualMemory(OperationCallback operation, ULONGLONG targetPid, size_t size, uint32_t allocationType, uint32_t protect, uintptr_t sourceAddress)
{
	PACKET_BASE packet{};

	packet.op = ALLOC_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	auto& serverRequest = packet.server.alloc_virtual_memory;

	serverRequest.targetPid = targetPid;
	serverRequest.sourceAddress = sourceAddress;

	serverRequest.allocationType = allocationType;
	serverRequest.protect = protect;

	serverRequest.size = size;
	serverRequest.code = STATUS_INTERRUPTED;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		printf(xor ("[+] Allocate virtual memory operation failed.\n"));
		return -1;
	}

	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	auto clientRequest = packet.client.alloc_virtual_memory;

	return clientRequest.targetAddress;
}

NTSTATUS Communication::ProtectVirtualMemory(OperationCallback operation, ULONGLONG targetPid, size_t size, uint32_t protect, uintptr_t sourceAddress)
{
	PACKET_BASE packet{};

	packet.op = PROTECT_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	auto& serverRequest = packet.server.protect_virtual_memory;

	serverRequest.targetPid = targetPid;
	serverRequest.sourceAddress = sourceAddress;

	serverRequest.protect = protect;

	serverRequest.size = size;
	serverRequest.code = STATUS_INTERRUPTED;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		printf(xor ("[+] Protect virtual memory operation failed.\n"));
		return -1;
	}

	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	auto clientRequest = packet.client.protect_virtual_memory;

	protect = clientRequest.protect;

	return NTSTATUS(clientRequest.code);
}

NTSTATUS Communication::FreeVirtualMemory(OperationCallback operation, ULONGLONG targetPid, uintptr_t address)
{
	PACKET_BASE packet{};

	packet.op = FREE_VIRTUAL_MEMORY;
	packet.side = SIDE::SERVER;
	packet.magic = 0xBEED0FEA;

	auto& serverRequest = packet.server.free_memory;

	serverRequest.targetPid = targetPid;
	serverRequest.address = address;

	serverRequest.code = STATUS_INTERRUPTED;

	constexpr ULONG firstCall = 1;

	auto veh = AddVectoredExceptionHandler(firstCall, [](PEXCEPTION_POINTERS exceptionHandler) -> LONG
		{
			auto context = exceptionHandler->ContextRecord;
			context->Rip += 8;

			return EXCEPTION_CONTINUE_EXECUTION;
		});

	if (!veh)
		return false;

	if (!operation(0x000004, 0x128, packet, 0xBEED0FEA, 0x1, 0x1))
	{
		printf(xor ("[+] Free virtual memory operation failed.\n"));
		return -1;
	}

	if (!RemoveVectoredExceptionHandler(veh))
		return false;

	auto clientRequest = packet.client.free_memory;

	return NTSTATUS(clientRequest.code);
}
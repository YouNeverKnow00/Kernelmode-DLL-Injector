#include "Loader.hpp"

enum OP_CODE : BYTE
{
	NONE = 11,
	TEST = 12,
	COPY_VIRTUAL_MEMORY = 14,
	GET_MODULE_BASE_SIZE = 17,
	ALLOC_VIRTUAL_MEMORY = 21,
	PROTECT_VIRTUAL_MEMORY = 33,
	FREE_VIRTUAL_MEMORY = 41
};

enum class SIDE : BYTE
{
	NONE,
	CLIENT,
	SERVER
};

struct TEST_S
{

};

struct TEST_C
{
	bool valid = false;
};

struct COPY_VIRTUAL_MEMORY_SERVER
{
	ULONGLONG targetPid;
	uintptr_t targetAddress;
	ULONGLONG sourcePid;
	uintptr_t sourceAddress;
	size_t size;
};

struct GET_MODULE_SERVER
{
	ULONGLONG pid;
	wchar_t name[32];
};

struct GET_MODULE_CLIENT
{
	uintptr_t baseAddress;
	size_t module_size;
};

struct ALLOC_VIRTUAL_MEMORY_SERVER
{
	ULONG targetPid, allocationType, protect;
	uintptr_t sourceAddress;
	uintptr_t targetAddress;
	size_t size;
	size_t code;
};

struct PROTECT_VIRTUAL_MEMORY_SERVER
{
	ULONG targetPid, protect;
	uintptr_t sourceAddress;
	size_t size;
	size_t code;
};

struct FREE_VIRTUAL_MEMORY_SERVER
{
	ULONG targetPid;
	uintptr_t address;
	size_t code;
};

struct PACKET_BASE
{
	OP_CODE op;
	SIDE side;
	uint32_t magic;

	union
	{
		union
		{
			TEST_S test;

			COPY_VIRTUAL_MEMORY_SERVER copy_virtual_memory;
			GET_MODULE_SERVER get_module;

			ALLOC_VIRTUAL_MEMORY_SERVER alloc_virtual_memory;
			PROTECT_VIRTUAL_MEMORY_SERVER protect_virtual_memory;

			FREE_VIRTUAL_MEMORY_SERVER free_memory;
		} server;

		union
		{
			TEST_C test;

			COPY_VIRTUAL_MEMORY_SERVER copy_virtual_memory;
			GET_MODULE_CLIENT get_module;

			ALLOC_VIRTUAL_MEMORY_SERVER alloc_virtual_memory;
			PROTECT_VIRTUAL_MEMORY_SERVER protect_virtual_memory;

			FREE_VIRTUAL_MEMORY_SERVER free_memory;
		} client;
	};
};

typedef BOOL(*OperationCallback)(ULONG iMode, ULONG magic, PACKET_BASE& packet, FLONG flRed, FLONG flGreen, FLONG flBlue);
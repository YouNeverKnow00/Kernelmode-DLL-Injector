#include "MemoryUtils.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <sstream>
#include <map>

#define Exit Sleep(1800); TerminateProcess(GetCurrentProcess(), 0)

#define NT_SUCCESS(x) ((x) >= 0)
#define INJECTED 2

MemoryUtils* memoryUtils = nullptr;

uint8_t* raw_data = 0;
size_t data_size = 0;

std::map<std::string, uint64_t> imports;

VOID DriverInit()
{
	if (!Mapper::MapDriver())
	{
		printf(xor ("[-] Failed to load driver.\n"));
		Exit;
	}
}

BOOL LoadLocalImage(const char* path)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);

	if (!file)
	{
		printf(xor ("[-] Dll not found.\n"));
		return FALSE;
	}

	std::ifstream::pos_type pos{ file.tellg() };

	data_size = pos;
	raw_data = new uint8_t[data_size];

	if (!raw_data)
		return FALSE;

	file.seekg(0, std::ios::beg);
	file.read((char*)raw_data, data_size);

	file.close();

	return TRUE;
}

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(uint64_t rva, PIMAGE_NT_HEADERS nt_header)
{
	PIMAGE_SECTION_HEADER section{ IMAGE_FIRST_SECTION(nt_header) };

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section++)
	{
		uint64_t size{ section->Misc.VirtualSize };

		if (!size)
			size = section->SizeOfRawData;

		if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size)))
			return section;
	}

	return 0;
}

uint64_t* GetPtrFromRVA(uint64_t rva, IMAGE_NT_HEADERS* nt_header, uint8_t* image_base)
{
	PIMAGE_SECTION_HEADER section_header{ GetEnclosingSectionHeader(rva, nt_header) };

	if (!section_header)
		return 0;

	int64_t delta{ (int64_t)(section_header->VirtualAddress - section_header->PointerToRawData) };

	return (uint64_t*)(image_base + rva - delta);
}

std::wstring AnsiToWstring(const std::string& input, DWORD locale = CP_UTF8)
{
	wchar_t buf[8192] = { 0 };
	MultiByteToWideChar(locale, 0, input.c_str(), (int)input.length(), buf, ARRAYSIZE(buf));
	return buf;
}

/*uint64_t GetFuncAddress(const char* module_name, const char* func)
{
	std::wstring module_name_utf = AnsiToWstring(string(module_name));

	uint64_t remote_module{ memoryUtils->GetModuleBase(module_name_utf) };

	if (!remote_module)
	{
		printf(xor ("[+] Failed to get module base from: %ws\n"), module_name_utf.c_str());
		Exit;
	}

	uint64_t local_module{ (uint64_t)GetModuleHandleA(module_name) };

	if (!local_module)
	{
		printf(xor ("[+] Failed to get module handle from: %s\n"), module_name);
		Exit;
	}

	uint64_t delta{ remote_module - local_module };

	return ((uint64_t)GetProcAddress((HMODULE)local_module, func) + delta);
}*/

BYTE RemoteLoaderWorkerCode[] =
{
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89,
	0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20,
	0x83, 0x38, 0x00, 0x75, 0x3D, 0x48, 0x8B, 0x44,
	0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40,
	0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8B,
	0x44, 0x24, 0x20, 0x48, 0x83, 0xC0, 0x18, 0x48,
	0x8B, 0xC8, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B,
	0x4C, 0x24, 0x20, 0x48, 0x89, 0x41, 0x10, 0x48,
	0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00,
	0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
};

typedef struct _REMOTE_LOADER
{
	int32_t Status;
	uintptr_t LoadLibraryFunc;
	uintptr_t OutModuleBase;
	char ModuleName[80];
} REMOTE_LOADER;

uintptr_t LoadRemoteLibrary(const char* moduleName, DWORD threadId)
{
	uintptr_t moduleBase = 0;

	HMODULE hNtdll = LoadLibraryW(xor (L"ntdll.dll"));

	DWORD workerCodeSize = sizeof(RemoteLoaderWorkerCode) + sizeof(REMOTE_LOADER);
	PVOID localCode = VirtualAlloc(NULL, workerCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	RtlCopyMemory(localCode, &RemoteLoaderWorkerCode, sizeof(RemoteLoaderWorkerCode));

	uint64_t workerBase = memoryUtils->AllocateMemory(4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	uintptr_t workerCode = (uintptr_t)workerBase + sizeof(RemoteLoaderWorkerCode);
	*(uintptr_t*)((uintptr_t)localCode + 0x6) = workerCode;

	REMOTE_LOADER* remoteLoader = (REMOTE_LOADER*)((uintptr_t)localCode + sizeof(RemoteLoaderWorkerCode));

	remoteLoader->LoadLibraryFunc = (uintptr_t)LoadLibraryA;
	strcpy_s(remoteLoader->ModuleName, 80, moduleName);

	memoryUtils->WriteMemory(workerBase, (uintptr_t)localCode, workerCodeSize);

	HHOOK hHook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)workerBase, hNtdll, threadId);

	while (remoteLoader->Status != INJECTED)
	{
		PostThreadMessage(threadId, WM_NULL, 0, 0);
		memoryUtils->ReadBuffer(workerCode, (PVOID)remoteLoader, sizeof(REMOTE_LOADER));
		Sleep(10);
	}

	moduleBase = remoteLoader->OutModuleBase;

	UnhookWindowsHookEx(hHook);

	NTSTATUS status = memoryUtils->FreeMemory(workerBase);

	if (!NT_SUCCESS(status))
	{
		printf(xor ("\n[-] Failed to free memory. Error: %p\n"), status);
		Exit;
	}

	VirtualFree(remoteLoader, 0, MEM_RELEASE);

	return moduleBase;
}
uint64_t GetRemoteProcAddress(const char* moduleName, const char* function)
{
	HMODULE hModule = LoadLibraryExA(moduleName, NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (!hModule)
	{
		printf(xor ("\n[-] Failed to load %s.\n"), moduleName);
		return 0;
	}

	uint64_t delta = (uint64_t)GetProcAddress(hModule, function);
	delta -= (uint64_t)hModule;

	FreeLibrary(hModule);

	return delta;
}

void SolveImports(PIMAGE_NT_HEADERS pNtHeader, uint8_t* localImage, DWORD threadId)
{
	auto importTable = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (!importTable.VirtualAddress || !importTable.Size)
		return;

	auto pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)GetPtrFromRVA((uint64_t)(importTable.VirtualAddress), pNtHeader, localImage);

	char* moduleName;
	while ((moduleName = (char*)GetPtrFromRVA((uint64_t)(pImportDescriptor->Name), pNtHeader, localImage)))
	{
		uintptr_t remoteBase;
		remoteBase = LoadRemoteLibrary(moduleName, threadId);

		if (!remoteBase)
		{
			printf(xor ("\n[-] Failed to get remote %s base.\n"), moduleName);
			return;
		}

		auto pImageThunkData = (PIMAGE_THUNK_DATA)GetPtrFromRVA((DWORD64)(pImportDescriptor->FirstThunk), pNtHeader, localImage);

		while (pImageThunkData->u1.AddressOfData)
		{
			if (pImageThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				pImageThunkData->u1.Function = remoteBase + GetRemoteProcAddress(moduleName, (LPCSTR)(pImageThunkData->u1.Ordinal & 0xFFFF));
			}
			else
			{
				IMAGE_IMPORT_BY_NAME* iibn = (IMAGE_IMPORT_BY_NAME*)GetPtrFromRVA((DWORD64)(pImageThunkData->u1.AddressOfData), pNtHeader, localImage);

				pImageThunkData->u1.Function = remoteBase + GetRemoteProcAddress(moduleName, (LPCSTR)iibn->Name);
			}

			pImageThunkData++;
		}
		pImportDescriptor++;
	}
}

void SolveRelocations(uint64_t base, uint64_t relocation_base, IMAGE_NT_HEADERS* nt_header)
{
	struct reloc_entry
	{
		ULONG to_rva;
		ULONG size;
		struct
		{
			WORD offset : 12;
			WORD type : 4;
		} item[1];
	};

	uintptr_t delta_offset = (uintptr_t)relocation_base - nt_header->OptionalHeader.ImageBase;

	if (!delta_offset)
		return;

	reloc_entry* reloc_ent = (reloc_entry*)GetPtrFromRVA((uint64_t)(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress), nt_header, (PBYTE)base);
	uintptr_t reloc_end = (uintptr_t)reloc_ent + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (reloc_ent == nullptr)
		return;

	while ((uintptr_t)reloc_ent < reloc_end && reloc_ent->size)
	{
		DWORD records_count = (reloc_ent->size - 8) >> 1;

		for (DWORD i = 0; i < records_count; i++)
		{
			WORD fix_type = (reloc_ent->item[i].type);
			WORD shift_delta = (reloc_ent->item[i].offset) % 4096;

			if (fix_type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (fix_type == IMAGE_REL_BASED_HIGHLOW || fix_type == IMAGE_REL_BASED_DIR64)
			{
				uintptr_t fix_va = (uintptr_t)GetPtrFromRVA((uint64_t)(reloc_ent->to_rva), nt_header, (PBYTE)base);

				if (!fix_va)
					fix_va = (uintptr_t)base;

				*(uintptr_t*)(fix_va + shift_delta) += delta_offset;
			}
		}

		reloc_ent = (reloc_entry*)((LPBYTE)reloc_ent + reloc_ent->size);
	}
}

void MapSections(uint64_t base, IMAGE_NT_HEADERS* nt_header)
{
	auto header{ IMAGE_FIRST_SECTION(nt_header) };
	size_t virtual_size{ 0 };
	size_t bytes{ 0 };

	while (nt_header->FileHeader.NumberOfSections && (bytes < nt_header->OptionalHeader.SizeOfImage))
	{
		memoryUtils->WriteMemory(base + header->VirtualAddress, (uintptr_t)(raw_data + header->PointerToRawData), header->SizeOfRawData);

		virtual_size = header->VirtualAddress;
		virtual_size = (++header)->VirtualAddress - virtual_size;

		bytes += virtual_size;
	}

	return;
}

BOOL ParseImports(uint64_t moduleBase)
{
	auto dos_header{ memoryUtils->Read< IMAGE_DOS_HEADER >(moduleBase) };
	auto nt_headers{ memoryUtils->Read< IMAGE_NT_HEADERS >(moduleBase + dos_header.e_lfanew) };
	auto descriptor{ memoryUtils->Read< IMAGE_IMPORT_DESCRIPTOR >(moduleBase + nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress) };

	int descriptor_count{ 0 };
	int thunk_count{ 0 };

	while (descriptor.Name)
	{
		auto first_thunk{ memoryUtils->Read< IMAGE_THUNK_DATA >(moduleBase + descriptor.FirstThunk) };
		auto original_first_thunk{ memoryUtils->Read< IMAGE_THUNK_DATA >(moduleBase + descriptor.OriginalFirstThunk) };
		thunk_count = 0;

		while (original_first_thunk.u1.AddressOfData)
		{
			char name[256];
			memoryUtils->ReadBuffer(moduleBase + original_first_thunk.u1.AddressOfData + 0x2, (LPVOID)name, 256);

			std::string str_name(name);
			auto thunk_offset{ thunk_count * sizeof(uintptr_t) };

			if (str_name.length() > 0)
				imports[str_name] = moduleBase + descriptor.FirstThunk + thunk_offset;

			++thunk_count;
			first_thunk = memoryUtils->Read< IMAGE_THUNK_DATA >(moduleBase + descriptor.FirstThunk + sizeof(IMAGE_THUNK_DATA) * thunk_count);
			original_first_thunk = memoryUtils->Read< IMAGE_THUNK_DATA >(moduleBase + descriptor.OriginalFirstThunk + sizeof(IMAGE_THUNK_DATA) * thunk_count);
		}

		++descriptor_count;
		descriptor = memoryUtils->Read< IMAGE_IMPORT_DESCRIPTOR >(moduleBase + nt_headers.OptionalHeader.DataDirectory[1].VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) * descriptor_count);
	}

	return (imports.size() > 0);
}

DWORD GetProcessInformationByWindow(LPCSTR WindowName, PDWORD pThreadId)
{
	DWORD processId = 0;

	while (!processId)
	{
		HWND hwnd = FindWindowA(NULL, WindowName);

		if (hwnd)
			*pThreadId = GetWindowThreadProcessId(hwnd, &processId);

		Sleep(100);
	}

	return processId;
}

int main()
{
	setlocale(0, "");

	printf(xor ("[+] Initializing operation callback...\n"));

	OperationCallback operation = Communication::Init(xor ("win32u"), xor ("NtGdiEngCreatePalette"));

	if (!operation)
	{
		printf(xor ("[+] Failed to init operation callback"));
		Exit;
	}

	printf(xor ("[+] Success!\n\n"));

	bool status = Communication::TestOperation(operation);

	if (!status)
	{
		printf(xor ("[-] Driver not loaded.\n"));
		Mapper::MapDriver();
	}
	else
	{
		printf(xor ("[+] Driver loaded!\n"));
	}

	Sleep(1200);

	DWORD threadId;
	DWORD processId = GetProcessInformationByWindow(xor ("WINDOW NAME"), &threadId); // WRITE WINDOW NAME

	if (processId == 0 && threadId == 0)
	{
		for (;; Sleep(100))
		{
			processId = GetProcessInformationByWindow(xor ("WINDOW NAME"), &threadId);  // WRITE WINDOW NAME

			if (processId != 0 && threadId != 0)
				break;
		}
	}

	cout << xor ("\n[+] Injecting...");

	memoryUtils = new MemoryUtils(operation, processId);

	string current_path = std::filesystem::current_path().string();
	string image_path = current_path + xor ("\\test.dll");  // WRITE DLL PATH

	if (!(LoadLocalImage(image_path.c_str())))
	{
		Exit;
	}

	if (!raw_data)
	{
		printf(xor ("[-] Image buffer is empty."));
		Exit;
	}

	uint8_t dll_stub[] = { "\x51\x52\x55\x56\x53\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\xB8\xFF\x00\xDE\xAD\xBE\xEF\x00\xFF\x48\xBA\xFF\x00\xDE\xAD\xC0\xDE\x00\xFF\x48\x89\x10\x48\x31\xC0\x48\x31\xD2\x48\x83\xEC\x28\x48\xB9\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\x48\x31\xD2\x48\x83\xC2\x01\x48\xB8\xDE\xAD\xC0\xDE\xDE\xAD\xC0\xDE\xFF\xD0\x48\x83\xC4\x28\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5B\x5E\x5D\x5A\x59\x48\x31\xC0\xC3" };

	IMAGE_DOS_HEADER* dos_header{ (IMAGE_DOS_HEADER*)raw_data };

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf(xor ("[-] Invalid PE."));
		Exit;
	}

	IMAGE_NT_HEADERS* nt_header{ (IMAGE_NT_HEADERS*)(&raw_data[dos_header->e_lfanew]) };

	if (nt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		printf(xor ("[-] Invalid NT header."));
		Exit;
	}

	uint64_t base{ memoryUtils->AllocateMemory(nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };

	if (!base)
	{
		printf(xor ("[-] Failed to allocate memory for local image."));
		Exit;
	}

	printf(xor ("\n[+] Local image base: %p\n"), base);

	uint64_t stub_base{ memoryUtils->AllocateMemory(sizeof(dll_stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) };

	if (!stub_base)
	{
		printf(xor ("[-] Failed to allocate memory for shellcode."));
		Exit;
	}

	printf(xor ("[Injector] Shellcode base: %p\n\n"), stub_base);


	PIMAGE_BASE_RELOCATION base_relocation{ (PIMAGE_BASE_RELOCATION)GetPtrFromRVA(
																		nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
																		nt_header,
																		raw_data) };
	if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		printf(xor ("[+] Fixing relocations...\n"));

		SolveRelocations((uint64_t)raw_data, base, nt_header);
	}

	SolveImports(nt_header, raw_data, threadId);

	uint64_t ProcessBase = memoryUtils->GetModuleBase(L"user32.dll");

	if (!ProcessBase)
	{
		printf(xor ("\n[-] Failed to get process base."));
		Exit;
	}

	printf(xor ("[Injector] Parsing imports...\n"));

	if (!ParseImports(ProcessBase))
	{
		printf(xor ("\n[-] Failed to parse imports."));
		Exit;
	}

	uint64_t iat_function_ptr{ imports[xor ("NtUserGetForegroundWindow")] };

	if (!iat_function_ptr)
	{
		printf(xor ("[-] Target import not found."));
		Exit;
	}

	uint64_t orginal_function_addr{ memoryUtils->Read<uint64_t>(iat_function_ptr) };

	printf(xor ("\n[+] IAT pointer: %p\n"), iat_function_ptr);

	*(uint64_t*)(dll_stub + 0x18) = iat_function_ptr;
	*(uint64_t*)(dll_stub + 0x22) = orginal_function_addr;

	memoryUtils->WriteMemory(base, (uintptr_t)raw_data, nt_header->FileHeader.SizeOfOptionalHeader + sizeof(nt_header->FileHeader) + sizeof(nt_header->Signature));

	printf(xor ("\n[+] Mapping sections...\n"));

	MapSections(base, nt_header);

	uint64_t entry_point{ (uint64_t)base + nt_header->OptionalHeader.AddressOfEntryPoint };

	*(uint64_t*)(dll_stub + 0x39) = (uint64_t)base;
	*(uint64_t*)(dll_stub + 0x4A) = entry_point;

	printf(xor ("\n[+] Entry Point: %p\n"), entry_point);

	memoryUtils->WriteMemory(stub_base, (uintptr_t)dll_stub, sizeof(dll_stub));
	memoryUtils->ProtectMemory(iat_function_ptr, sizeof(uint64_t), PAGE_READWRITE);
	memoryUtils->WriteMemory(iat_function_ptr, (uintptr_t)&stub_base, sizeof(uint64_t));

	Sleep(3000);

	if (iat_function_ptr != NULL)
	{
		memoryUtils->ProtectMemory(iat_function_ptr, sizeof(uint64_t), PAGE_READONLY);

		delete[] raw_data;

		printf(xor ("\n[+] Done!"));

		Sleep(1500);
	}

	return EXIT_SUCCESS;
}
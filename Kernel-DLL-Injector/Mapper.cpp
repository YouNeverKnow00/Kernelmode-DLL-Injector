#include "Mapper.hpp"
#include "kdmapper.hpp"

#define Close (Sleep)(1800); TerminateProcess(GetCurrentProcess(), 0)

HANDLE iqvw64e_device_handle;

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	std::cout << xor ("[!!] Crash at addr 0x") << ExceptionInfo->ExceptionRecord->ExceptionAddress << xor (" by 0x") << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl;

	if (iqvw64e_device_handle)
		intel_driver::Unload(iqvw64e_device_handle);

	return EXCEPTION_EXECUTE_HANDLER;
}

BOOL Mapper::MapDriver()
{
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	srand((unsigned)time(NULL) * GetCurrentThreadId());

	if (intel_driver::IsRunning())
	{
		std::cout << xor ("\n[-] Driver is already in use.") << std::endl;
		Close;
	}

	iqvw64e_device_handle = intel_driver::Load();

	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << xor ("\n[-] Failed to load driver.") << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		Close;
	}

	if (!intel_driver::ClearPiDDBCacheTable(iqvw64e_device_handle)) {
		std::cout << xor ("\n[-] Failed to Clean traces #1") << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		Close;
	}

	if (!intel_driver::ClearKernelHashBucketList(iqvw64e_device_handle)) {
		std::cout << xor ("\n[-] Failed to Clean traces #2") << std::endl;
		Close;
	}

	if (!intel_driver::ClearMmUnloadedDrivers(iqvw64e_device_handle)) {
		std::cout << xor ("\n[-] Failed to Clean traces #3") << std::endl;
		Close;
	}

	if (!kdmapper::MapDriver(iqvw64e_device_handle))
	{
		std::cout << xor ("\n[-] Failed to map driver.") << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		Close;
	}

	intel_driver::Unload(iqvw64e_device_handle);
	std::cout << xor ("\n[+] driver mapped!") << std::endl;

	return TRUE;
}
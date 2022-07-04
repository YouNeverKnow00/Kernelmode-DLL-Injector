#include "ProcessUtils.hpp"

#include <TlHelp32.h>

DWORD ProcessUtils::GetProcessID(string processName)
{
	if (processName.empty())
		return NULL;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (hSnap == INVALID_HANDLE_VALUE)
		return NULL;

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);

	if (Process32First(hSnap, &pe))
	{
		while (Process32Next(hSnap, &pe))
		{
			if (!strcmp(pe.szExeFile, processName.c_str()))
			{
				CloseHandle(hSnap);
				return pe.th32ProcessID;
			}
		}
	}

	CloseHandle(hSnap);

	return NULL;
}
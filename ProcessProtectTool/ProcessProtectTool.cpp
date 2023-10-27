#include "ProcessProtectTool.h"
#include <Windows.h>
#include <iostream>
#include <vector>

using namespace std;

vector<DWORD> ParsePids(const wchar_t* buffer[], int count) {
	std::vector<DWORD> pids;
	for (int i = 0; i < count; i++)
		pids.push_back(::_wtoi(buffer[i]));
	return pids;
}


void PrintUsage() {
	cout << "PrintUsage" << endl;
}

void Error(const char str[]) {
	cout << str << endl;
}

void wmain(int argc, const wchar_t* argv[]) {
	if (argc < 2)
	{
		PrintUsage();
		return;
	}
		
	enum class Options {
		Unknown,
		Add, Remove, Clear
	};
	Options option;
	if (::_wcsicmp(argv[1], L"add") == 0)
		option = Options::Add;
	else if (::_wcsicmp(argv[1], L"remove") == 0)
		option = Options::Remove;
	else if (::_wcsicmp(argv[1], L"clear") == 0)
		option = Options::Clear;
	else {
		cout << "Unknown option" << endl;
		PrintUsage();
		return;
	}
	HANDLE hFile = ::CreateFile(L"\\\\.\\" PROCESS_PROTECT_NAME,
		GENERIC_WRITE | GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		Error("Failed to open device");
		return;
	}
		
	
	std::vector<DWORD> pids;
	BOOL success = FALSE;
	DWORD bytes;
	switch (option) {
	case Options::Add:
		pids = ParsePids(argv + 2, argc - 2);
		success = ::DeviceIoControl(hFile, IOCTL_PROCESS_PROTECT_BY_PID,
			pids.data(), static_cast<DWORD>(pids.size()) * sizeof(DWORD),
			nullptr, 0, &bytes, nullptr);
		break;
	case Options::Remove:
		pids = ParsePids(argv + 2, argc - 2);
		success = ::DeviceIoControl(hFile, IOCTL_PROCESS_UNPROTECT_BY_PID,
			pids.data(), static_cast<DWORD>(pids.size()) * sizeof(DWORD),
			nullptr, 0, &bytes, nullptr);
		break;
	case Options::Clear:
		success = ::DeviceIoControl(hFile, IOCTL_PROCESS_PROTECT_CLEAR,
			nullptr, 0, nullptr, 0, &bytes, nullptr);
		break;
	}
	if (!success)
	{
		Error("Failed in DeviceIoControl");
		return;
	}
		
	printf("Operation succeeded.\n");
	::CloseHandle(hFile);
	return;
}
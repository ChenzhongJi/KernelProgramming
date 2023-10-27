// SysMonClient.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <string>
#include <Windows.h>
#include "../RegistryMoniter/RegistryMoniterCommon.h"

int Error(const char* text) {
	printf("%s (%d)\n", text, ::GetLastError());
	return 1;
}

void DisplayTime(const LARGE_INTEGER& time) {
	SYSTEMTIME st;
	::FileTimeToSystemTime((FILETIME*)&time, &st);
	printf("%02d:%02d:%02d.%03d: ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}

void DisplayBinary(const UCHAR* buffer, DWORD size) {
	for (DWORD i = 0; i < size; i++)
		printf("%02X ", buffer[i]);
	printf("\n");
}

void DisplayInfo(BYTE* buffer, DWORD size) {
	auto count = size;
	while (count > 0) {
		auto header = (ItemHeader*)buffer;
		switch (header->Type) {
		case ItemType::RegistrySetValue:
		{
			DisplayTime(header->Time);
			auto info = (RegistrySetValueInfo*)buffer;
			printf("Registry write PID=%d: %ws\\%ws type: %d size: %d data: ", info->ProcessId,
				info->KeyName, info->ValueName, info->DataType, info->DataSize);
			switch (info->DataType) {
			case REG_DWORD:
				printf("0x%08X\n", *(DWORD*)info->Data);
				break;

			case REG_SZ:
			case REG_EXPAND_SZ:
				printf("%ws\n", (WCHAR*)info->Data);
				break;

			case REG_BINARY:
				DisplayBinary(info->Data, min(info->DataSize, sizeof(info->Data)));
				break;

			default:
				DisplayBinary(info->Data, min(info->DataSize, sizeof(info->Data)));
				break;

			}

			break;
		}

		default:
			break;
		}
		buffer += header->Size;
		count -= header->Size;
	}

}

int main() {
	auto hFile = ::CreateFile(L"\\\\.\\sysmon", GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return Error("Failed to open file");

	BYTE buffer[1 << 16];

	while (true) {
		DWORD bytes;
		if (!::ReadFile(hFile, buffer, sizeof(buffer), &bytes, nullptr))
			return Error("Failed to read");

		if (bytes != 0)
			DisplayInfo(buffer, bytes);

		::Sleep(200);
	}
}


#pragma once

enum class ItemType : short {
	None,
	RegistrySetValue
};

struct ItemHeader {
	ItemType Type;
	USHORT Size;
	LARGE_INTEGER Time;
};

struct RegistrySetValueInfo : ItemHeader {
	ULONG ProcessId;
	ULONG ThreadId;
	WCHAR KeyName[256];		// full key name
	WCHAR ValueName[64];	// value name
	ULONG DataType;			// REG_xxx
	UCHAR Data[128];		// data
	ULONG DataSize;			// size of data
};

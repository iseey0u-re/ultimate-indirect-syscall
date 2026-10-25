#include "include/main.hpp"


PPEB getPEB() {
	return reinterpret_cast<PPEB>(__readgsqword(0x60));
}

std::vector<int> Syscall::GetNumberOfNames() {
	std::vector<int> idsNts{};
	idsNts.reserve(500);

	PPEB peb = getPEB();
	PPEB_LDR_DATA ldr = reinterpret_cast<PPEB_LDR_DATA>(peb->Ldr);

	PLIST_ENTRY ListHead = reinterpret_cast<PLIST_ENTRY>(&ldr->InMemoryOrderModuleList);
	PLIST_ENTRY exeModule = reinterpret_cast<PLIST_ENTRY>(ListHead->Flink);

	PLIST_ENTRY ntdllModule = reinterpret_cast<PLIST_ENTRY>(exeModule->Flink);
	PLDR_DATA_TABLE_ENTRY_FULL entry = CONTAINING_RECORD(ntdllModule, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);

	DWORD64 dllBase = reinterpret_cast<DWORD64>(entry->DllBase);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
	PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)(dllBase + dosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY)ntHeader->OptionalHeader.DataDirectory;

	if (dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 || dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) {
		return idsNts;
	}

	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(dllBase + dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	for (size_t i = 0; i < exportDir->NumberOfNames; ++i) {
		DWORD64 currentElement = (DWORD64)((dllBase + exportDir->AddressOfNames) + (sizeof(DWORD) * i));
		DWORD nameRVA = *(DWORD*)(currentElement);
		const char* FuncName = (const char*)(dllBase + nameRVA);
		if (strncmp(FuncName, "Nt", 2) == 0 || strncmp(FuncName, "Zw", 2) == 0) {
			//printf("Added to Vector %s\n", FuncName);
			idsNts.push_back(i);

		}
	}
	return idsNts;
}


DWORD64 Syscall::GetAddrFunc(const std::string& Name) {
	PPEB peb = getPEB();
	PPEB_LDR_DATA ldr = reinterpret_cast<PPEB_LDR_DATA>(peb->Ldr);

	PLIST_ENTRY ListHead = reinterpret_cast<PLIST_ENTRY>(&ldr->InMemoryOrderModuleList);
	PLIST_ENTRY exeModule = reinterpret_cast<PLIST_ENTRY>(ListHead->Flink);

	PLIST_ENTRY ntdllModule = reinterpret_cast<PLIST_ENTRY>(exeModule->Flink);
	PLDR_DATA_TABLE_ENTRY_FULL entry = CONTAINING_RECORD(ntdllModule, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);

	DWORD64 dllBase = reinterpret_cast<DWORD64>(entry->DllBase);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
	PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)(dllBase + dosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY)ntHeader->OptionalHeader.DataDirectory;

	if (dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 || dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) {
		return 0;
	}

	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(dllBase + dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	for (size_t i = 0; i < exportDir->NumberOfNames; ++i) {
		DWORD64 currentElement = (DWORD64)((dllBase + exportDir->AddressOfNames) + (sizeof(DWORD) * i));
		DWORD nameRVA = *(DWORD*)(currentElement);
		const char* FuncName = (const char*)(dllBase + nameRVA);
		if (strcmp(FuncName, Name.c_str()) == 0) {

			DWORD64 addrOrdinal = (DWORD64)((dllBase + exportDir->AddressOfNameOrdinals) + (sizeof(WORD) * i));
			WORD ordinal = *(WORD*)(addrOrdinal); // ordinal

			DWORD64 addrFunc = (DWORD64)((dllBase + exportDir->AddressOfFunctions) + (sizeof(DWORD) * ordinal));
			DWORD funcRVA = *(DWORD*)(addrFunc); // Function RVA


			return (DWORD64)(dllBase + funcRVA);
		}
	}

	return 0;

}


SmallStubInfo Syscall::GetAllAddrFunc(int counter) {
	SmallStubInfo info;

	PPEB peb = getPEB();
	PPEB_LDR_DATA ldr = reinterpret_cast<PPEB_LDR_DATA>(peb->Ldr);

	PLIST_ENTRY ListHead = reinterpret_cast<PLIST_ENTRY>(&ldr->InMemoryOrderModuleList);
	PLIST_ENTRY exeModule = reinterpret_cast<PLIST_ENTRY>(ListHead->Flink);

	PLIST_ENTRY ntdllModule = reinterpret_cast<PLIST_ENTRY>(exeModule->Flink);
	PLDR_DATA_TABLE_ENTRY_FULL entry = CONTAINING_RECORD(ntdllModule, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);

	DWORD64 dllBase = reinterpret_cast<DWORD64>(entry->DllBase);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBase;
	PIMAGE_NT_HEADERS64 ntHeader = (PIMAGE_NT_HEADERS64)(dllBase + dosHeader->e_lfanew);
	PIMAGE_DATA_DIRECTORY dataDirectory = (PIMAGE_DATA_DIRECTORY)ntHeader->OptionalHeader.DataDirectory;

	if (dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 || dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0) {
		return info;
	}

	PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(dllBase + dataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD64 currentElement = (DWORD64)((dllBase + exportDir->AddressOfNames) + (sizeof(DWORD) * counter));
	DWORD nameRVA = *(DWORD*)(currentElement);
	const char* FuncName = (const char*)(dllBase + nameRVA);


	DWORD64 addrOrdinal = (DWORD64)((dllBase + exportDir->AddressOfNameOrdinals) + (sizeof(WORD) * counter));
	WORD ordinal = *(WORD*)(addrOrdinal); // ordinal

	DWORD64 addrFunc = (DWORD64)((dllBase + exportDir->AddressOfFunctions) + (sizeof(DWORD) * ordinal));
	DWORD funcRVA = *(DWORD*)(addrFunc); // Function RVA
	
	info.Name = FuncName;
	info.StubStartAddress = (DWORD64)(dllBase + funcRVA);

	return info;
}

#include "include/main.hpp"

uintptr_t Syscall::GetTESTaddr(uintptr_t StartStubAddr) {
	// F6 04 bytes need find 
	unsigned char* bytes = reinterpret_cast<unsigned char*>(StartStubAddr); //  test byte ptr ds:[7FFE0308], 1  example from ntdll stub

	for (size_t i = 0; i < 28; i++) {
		if (bytes[i] == 0xF6 && bytes[i + 1] == 0x04) {
			return reinterpret_cast<uintptr_t>(&bytes[i]);
		}

		if (bytes[i] == 0xC3) break;
	}

	return 0; // NOT FOUND

}


uintptr_t Syscall::GetSyscallAddr(uintptr_t StartStubAddr) {
	unsigned char* bytes = reinterpret_cast<unsigned char*>(StartStubAddr);

	for (size_t i = 0; i < 28; i++) {
		if (bytes[i] == 0xF6 && bytes[i + 1] == 0x04) {
			for (size_t j = i + 5; j < 32; j++) {
				if (bytes[j] == 0x0F && bytes[j + 1] == 0x05) { // OF05 - syscall bytes x64

					return StartStubAddr + j;

					break;
				}
				if (bytes[j] == 0xC3) break;
			}
		}

		if (bytes[i] == 0xC3) break;
	}

	return 0; // NOT FOUND
}

int Syscall::GetSSN(uintptr_t StartStubAddr) { //if without hook
	unsigned char* bytes = reinterpret_cast<unsigned char*>(StartStubAddr);

	for (size_t i = 0; i < 28; i++) {
		if (bytes[i] == 0xB8) {
			return *reinterpret_cast<const int*>(&bytes[i + 1]);
		}
	}

	return SSN_NOT_FOUND;
}

bool Syscall::IsHooked(uintptr_t StartStubAddr) {
	unsigned char* bytes = reinterpret_cast<unsigned char*>(StartStubAddr);

	if (bytes[0] != 0x4C || bytes[1] != 0x8b || bytes[2] != 0xd1) { // mov r10, rcx
		return true; // Hooked
	}

	return false; // Not hooked
}




static bool ScanRegionSEH(BYTE* regionStart, BYTE* regionEnd,
	DWORD64 AddressFromStub, DWORD* outSSN)
{
	const BYTE SIG_MOV10_RCX[] = { 0x4C, 0x8B, 0xD1 };
	const BYTE MOV_EAX[] = { 0xB8 };
	const BYTE JMP[] = { 0xFF, 0x25 };

	__try
	{
		for (BYTE* p = regionStart; p + 8 <= regionEnd; ++p)
		{
			if (p[0] == SIG_MOV10_RCX[0] && p[1] == SIG_MOV10_RCX[1] && p[2] == SIG_MOV10_RCX[2])
			{
				BYTE* maxSearchAddr = (p + 64 < regionEnd) ? (p + 64) : regionEnd;
				for (BYTE* i = p; i + 5 <= maxSearchAddr; ++i)
				{
					if (i[0] == MOV_EAX[0])
					{
						DWORD SSN = *reinterpret_cast<DWORD*>(i + 1);
						for (BYTE* y = i; y + 10 <= maxSearchAddr; ++y)
						{
							if (y[0] == JMP[0] && y[1] == JMP[1])
							{
								DWORD64 target = *reinterpret_cast<DWORD64*>(y + 6);
								if (target == AddressFromStub) { *outSSN = SSN; return true; }
							}
						}
					}
				}
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { return false; }

	return false;
}



int Syscall::FindSSN(uintptr_t AddressFromStub) {
	DWORD64 VirtualQueryAddr = GetAddrFunc("NtQueryVirtualMemory"); // This function is usually not hooked
	auto NtQueryVirtualMemory = reinterpret_cast<pfnNtQueryVirtualMemory>(VirtualQueryAddr);

	const BYTE SIG_MOV10_RCX[] = { 0x4C, 0x8B, 0xD1 }; // mov r10, rcx
	const BYTE MOV_EAX[] = { 0xB8 };             // mov eax, imm32
	const BYTE JMP[] = { 0xFF, 0x25 };             // jmp qword ptr [rip+0]

	BYTE* addr = reinterpret_cast<BYTE*>(0x10000);
	BYTE* maxAddr = reinterpret_cast<BYTE*>(0x00007FFFFFFEFFFFULL);


	MEMORY_BASIC_INFORMATION mbi{0};
	SIZE_T returnLength = 0;

	while (addr < maxAddr)
	{
		
		if (NtQueryVirtualMemory(((HANDLE)(LONG_PTR)-1), addr, MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength) != 0) { 
			break;
		}


		if (mbi.Type == MEM_PRIVATE &&
			mbi.State == MEM_COMMIT &&
			(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
				PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
			!(mbi.Protect & PAGE_GUARD))
		{
			BYTE* regionStart = reinterpret_cast<BYTE*>(mbi.BaseAddress);
			BYTE* regionEnd = regionStart + mbi.RegionSize;

			DWORD ssn = 0;
			if (ScanRegionSEH(regionStart, regionEnd, AddressFromStub, &ssn))
				return ssn;
		}

		addr = reinterpret_cast<BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
	}
	return SSN_NOT_FOUND;
}


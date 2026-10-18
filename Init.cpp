#include "include/main.hpp"

int          Syscall::ssnNOW = 0;
uintptr_t    Syscall::syscallAddrNOW = 0;
bool         Syscall::IsHookedNOW = false;
bool         Syscall::IsBrokenNOW = false;
std::vector<StubInfo> Syscall::vecStubInfo;


bool Syscall::Init(std::string Name) {

	for (StubInfo& SI : Syscall::vecStubInfo) {
		if (SI.Name == Name) {
			//printf("Found! %s\n", Name.c_str());
			Syscall::ssnNOW = SI.SSN;
			Syscall::syscallAddrNOW = SI.SyscallAddr;
			Syscall::IsHookedNOW = SI.isHooked;
			Syscall::IsBrokenNOW = SI.IsBroken;
			return true;
		}

	}

	return false;
}


void Syscall::Handler(SmallStubInfo info) {
	std::string Name = info.Name;
	uintptr_t StubStartAddr = info.StubStartAddress;
	StubInfo mainInfo;

	// Temp Info ====

	bool hooked = Syscall::IsHooked(StubStartAddr);
	uintptr_t syscallAddr = Syscall::GetSyscallAddr(StubStartAddr);
	uintptr_t testAddr = Syscall::GetTESTaddr(StubStartAddr);
	int SSNhook = SSN_NOT_FOUND;
	if (hooked) {
		SSNhook = Syscall::FindSSN(testAddr);
	}

	int SSNwoHook = Syscall::GetSSN(StubStartAddr);
	
	
	
	// END ====



	if (testAddr == 0 || SSNhook == SSN_NOT_FOUND && hooked == true) {
		mainInfo.IsBroken = true; 
	}
	else if (SSNwoHook == SSN_NOT_FOUND && hooked == false) {
		mainInfo.IsBroken = true;
	}
	else {
		mainInfo.IsBroken = false;
	}
	
	mainInfo.isHooked = hooked;
	mainInfo.Name = Name;

	mainInfo.SyscallAddr = syscallAddr;

	if (hooked) {
		mainInfo.SSN = SSNhook;
	}
	else {

		mainInfo.SSN = SSNwoHook;
	}

		

	Syscall::vecStubInfo.push_back(mainInfo);
	return;
}

void Syscall::InitConstructor() {
	std::vector<int> ids = Syscall::GetNumberOfNames();
	Syscall::vecStubInfo.reserve(ids.size());

	for (int& i : ids) {
		SmallStubInfo info = Syscall::GetAllAddrFunc(i);
		Handler(info);
		//printf("InitConstructor #%d | Name: %s\n", i, info.Name.c_str());
	}

}
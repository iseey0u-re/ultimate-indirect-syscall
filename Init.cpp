#include "include/main.hpp"

thread_local Syscall* Syscall::s_activeInstance = nullptr;

Syscall::Syscall() {
    InitConstructor();
}

void Syscall::InitConstructor() {
    vecStubInfo.clear();
    std::vector<int> ids = GetNumberOfNames();
    vecStubInfo.reserve(ids.size());

    for (int& i : ids) {
        SmallStubInfo info = GetAllAddrFunc(i);
        Handler(info);
    }
}

void Syscall::Handler(const SmallStubInfo& info) {
    std::string Name = info.Name;
    uintptr_t StubStartAddr = info.StubStartAddress;
    StubInfo mainInfo;

    bool hooked = IsHooked(StubStartAddr);
    uintptr_t syscallAddr = GetSyscallAddr(StubStartAddr);
    uintptr_t testAddr = GetTESTaddr(StubStartAddr);
    int SSNhook = SSN_NOT_FOUND;

    if (hooked) {
        SSNhook = FindSSN(testAddr);
    }

    int SSNwoHook = GetSSN(StubStartAddr);

    if (testAddr == 0 || (SSNhook == SSN_NOT_FOUND && hooked)) {
        mainInfo.IsBroken = true;
    }
    else if (SSNwoHook == SSN_NOT_FOUND && !hooked) {
        mainInfo.IsBroken = true;
    }
    else {
        mainInfo.IsBroken = false;
    }

    mainInfo.isHooked = hooked;
    mainInfo.Name = Name;
    mainInfo.SyscallAddr = syscallAddr;
    mainInfo.SSN = hooked ? SSNhook : SSNwoHook;

    vecStubInfo.push_back(mainInfo);
}

bool Syscall::Init(const std::string& Name) {
    for (const StubInfo& SI : vecStubInfo) {
        if (SI.Name == Name) {
            ssnNOW = SI.SSN;
            syscallAddrNOW = SI.SyscallAddr;
            IsHookedNOW = SI.isHooked;
            IsBrokenNOW = SI.IsBroken;

            s_activeInstance = this;
            return true;
        }
    }
    return false;
}


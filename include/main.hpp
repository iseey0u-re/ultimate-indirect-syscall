#pragma once
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>

#include "syscall_types.hpp"
#include "types.hpp"

class Syscall {
private:

    int ssnNOW{ 0 };
    uintptr_t syscallAddrNOW{ 0 };
    bool IsHookedNOW{ false };
    bool IsBrokenNOW{ false };

    std::vector<StubInfo> vecStubInfo;

    static thread_local Syscall* s_activeInstance;

    void Handler(const SmallStubInfo& info);
    void InitConstructor();

    static uintptr_t GetTESTaddr(uintptr_t StartStubAddr);
    static uintptr_t GetSyscallAddr(uintptr_t StartStubAddr);
    static int GetSSN(uintptr_t StartStubAddr);
    static bool IsHooked(uintptr_t StartStubAddr);
    static SmallStubInfo GetAllAddrFunc(int counter);
    static std::vector<int> GetNumberOfNames();
    int FindSSN(uintptr_t AddressFromStub);

public:
    Syscall();
    ~Syscall() = default;

    Syscall(const Syscall&) = delete;
    Syscall& operator=(const Syscall&) = delete;

    bool Init(const std::string& Name);
    DWORD64 GetAddrFunc(const std::string& Name);

    static NTSTATUS syscall();
};

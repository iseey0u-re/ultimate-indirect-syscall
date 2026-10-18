#pragma once
#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>

#include "syscall_types.hpp"
#include "types.hpp"


class Syscall {
private:
    static int ssnNOW;
    static uintptr_t syscallAddrNOW;
    static bool IsHookedNOW;
    static bool IsBrokenNOW;

    static std::vector<StubInfo> vecStubInfo;
public:
    Syscall() {
        Syscall::InitConstructor();
    }
   
    static uintptr_t GetTESTaddr(uintptr_t StartStubAddr);
    static uintptr_t GetSyscallAddr(uintptr_t StartStubAddr);
    static int GetSSN(uintptr_t StartStubAddr);
    static bool IsHooked(uintptr_t StartStubAddr);
    static SmallStubInfo GetAllAddrFunc(int counter);
    static std::vector<int> GetNumberOfNames();
    static bool Init(std::string Name); // return True if it was initialized
    static void Handler(SmallStubInfo info);
    static void InitConstructor();
    static int FindSSN(uintptr_t AddressFromStub);
    static PPEB getPEB();
    static DWORD64 GetAddrFunc(std::string Name);

    static NTSTATUS syscall();

};


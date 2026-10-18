#pragma once

#include <windows.h>


extern "C" void SaveArguments();
extern "C" NTSTATUS PseudoStub(int SSN, uintptr_t SyscallAddress);

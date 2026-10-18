#include "include/main.hpp"


NTSTATUS Syscall::syscall() {
	SaveArguments(); // .asm file
	if (Syscall::IsBrokenNOW == true) { return IS_BROKEN; }
	NTSTATUS status = PseudoStub(Syscall::ssnNOW, Syscall::syscallAddrNOW); 

	return status;
}
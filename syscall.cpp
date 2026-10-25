#include "include/main.hpp"


NTSTATUS Syscall::syscall() {
	SaveArguments(); // .asm file
    if (s_activeInstance == nullptr) {
        return IS_BROKEN; 
    }
    if (s_activeInstance->IsBrokenNOW == true) {
        return IS_BROKEN;
    }

    NTSTATUS status = PseudoStub(s_activeInstance->ssnNOW, s_activeInstance->syscallAddrNOW);
	return status;
}

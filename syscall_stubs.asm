.code

PUBLIC SaveArguments
PUBLIC PseudoStub

SaveArguments PROC

	mov r10, rcx
	mov qword ptr [rsp + 10h], rdx

	ret

SaveArguments ENDP


PseudoStub PROC
	sub rsp, 28h
	mov eax, ecx ; SSN 
	mov r11, rdx ; syscall address
	
	mov rdx, qword ptr [rsp + 8h]
	add rsp, 28h
	jmp r11
	
	
	ret

PseudoStub ENDP



END
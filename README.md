# Ultimate Indirect Syscall

## How to Use

To use this project, you must include the main header file in your source code:

    #include "include/main.hpp"

You must initialize the `Syscall` class beforehand so that everything is populated and ready for work.

For example, if we want to call `NtTerminateProcess`, we first need to call `Init("NtName")`. 
It returns `bool`. If it returns `false`, an error occurred — either the SSN could not be found or some other issue. 
If it returns `true`, we can proceed to the next step.

The next step is simply casting the address of `sys.syscall` to the type of the required function.

### Example

    #include "include/main.hpp"

    Syscall sys;
    
    typedef NTSTATUS(NTAPI* NtTerminateProcess_t)(
        HANDLE ProcessHandle,
        NTSTATUS ExitStatus
    );
    
    sys.Init("NtTerminateProcess");
    
    NtTerminateProcess_t NtTerminateProcess = reinterpret_cast<NtTerminateProcess_t>(&sys.syscall);
    
    NtTerminateProcess(hProcess, 0);

### Sequential Calls

`Init` must always be called before the actual call. You can define all required types first, and then do the calls:

    sys.Init("NtTerminateProcess");
    NtTerminateProcess(hProcess, 0);
    
    sys.Init("NtClose");
    NtClose(hProcess);


## Requirements & Build

- **Architecture:** x64 only.
- **Compiler:** MSVC (Visual Studio 2019/2022).
- **Assembler:** MASM (Microsoft Macro Assembler) must be enabled for `syscall_stubs.asm`.

To build the project, compile the source files using MSVC for **Release x64**. Ensure that the `syscall_stubs.asm` file has its `Item Type` set to `Microsoft Macro Assembler`.
## How It Works

Every hooker (EDR/AV) must keep a copied clean stub of the hooked function in a separate, dynamically allocated memory region. This method looks for such a stub by scanning all memory, specifically looking for `MEM_PRIVATE` and simultaneously executable memory regions.

If nothing is hooked, the SSN is simply copied from the original `ntdll` stub. That is why the method is universal — it works both for hooked and unhooked functions.

It searches for the bytes `mov r10, rcx` and `mov eax, imm32`. 

Most importantly, since you cannot perform a `jmp rel32` (relative jump) from that allocated memory region to the actual `ntdll` address — a relative jump only covers a limited offset and cannot guarantee reaching an arbitrary address in memory — the hooker uses `jmp qword ptr [rip+0]` instead. This provides an **absolute jump** to anywhere. 

The essence of `rip+0` is that it reads the 8 bytes immediately following this instruction as a 64-bit absolute address. The hooker writes the address of the original ntdll instruction into these 8 bytes. 

Specifically, it points to the instruction `test byte ptr ds:[7FFE0308], 1`. This is a crucial check that cannot be erased. Therefore, they erase `mov r10, rcx` and `mov eax, imm32`, place a `jmp` at the beginning, and fill the empty space with junk. Since the program shouldn't crash, it must jump to the `test` instruction so it works on all systems.

The code simply copies the address of this instruction and compares it with the bytes after `jmp qword ptr [rip+0]`. If they match, it means these stubs are identical, meaning the SSN can be safely copied from this clean stub and used.

### Example of a Clean Stub Left by a Hooker

This is how a clean stub looks in a `MEM_PRIVATE` executable memory region allocated by the hooker. The original `mov r10, rcx` and `mov eax, 2C` are still intact, followed by the `jmp qword ptr [rip+0]` absolute jump:

    00007FF959700000 | 4C:8BD1          | mov r10,rcx
    00007FF959700003 | B8 2C000000      | mov eax,2C
    00007FF959700008 | FF25 00000000    | jmp qword ptr ds:[7FF95970000E]
    00007FF95970000E | 38D6             | ...
    00007FF959700010 | 58               | ...
    00007FF959700011 | 59               | ...
    00007FF959700012 | F9               | ...
    00007FF959700013 | 7F 00            | ...

The bytes starting at `00007FF95970000E` are not real instructions. They represent the 8-byte absolute address written in little-endian format. For example, the bytes `38 D6 58 59 F9 7F 00 00` form the address `0x00007FF95958D638`, which points to the original `ntdll` instruction `test byte ptr ds:[7FFE0308], 1`. The disassembler simply tries to decode these bytes as code, but in reality they are just a 64-bit pointer.
## Explanation

This method is not the best; there are much more stable alternatives (Hell's Gate, Tartarus, Freshy Syscalls, etc.). However, this method demonstrates an alternative way to find the SSN: instead of trying to restore it, it simply finds what the hooker left behind. 

It won't work on all hookers, but the code is easy to modify. At any time, you can change the functions in `Finder.cpp` to make it more universal.

## Warning

This code is not malicious and was not created to harm anyone's computer. I am not responsible for any damage caused by this code. It merely demonstrates an unusual method of resolving SSNs with a convenient wrapper. I do not encourage its use in malicious software. It is created for reading and analysis by malware analysts, reverse engineers, and low-level developers.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

# clad
clad - command line assembler/disassembler

## What's this?
Clad allows you to assemble/disassemble code from and to strings. This allows
you to easily explore the instruction sets of various CPU architectures, get hex
code for you reverse engineering needs, and more.

## Examples
### Simple function
For example, this is how a function which returns the constant 0x0f00 looks
like on amd64:
```
$ clad -a 'push rbp; mov rbp, rsp; mov eax, 0x0f00; pop rbp; ret' 
0x0000 | 55 | push rbp
0x0001 | 48 89 e5 | mov rbp, rsp
0x0004 | b8 00 0f 00 00 | mov eax, 0x0f00
0x0009 | 5d | pop rbp
0x000a | c3 | ret
```
To make it prettier:
```
$ clad -a 'push rbp; mov rbp, rsp; mov eax, 0x0f00; pop rbp; ret' | column -s '|' -t
0x0000    55                push rbp
0x0001    48 89 e5          mov rbp, rsp
0x0004    b8 00 0f 00 00    mov eax, 0x0f00
0x0009    5d                pop rbp
0x000a    c3                ret
```
This is how you can derive it from the hex values:
```
$ clad '55 48 89 e5 b8 00 0f 00 00 5d c3' | column -s'|' -t
0x0000    55                push rbp
0x0001    48 89 e5          mov rbp, rsp
0x0004    b8 00 0f 00 00    mov eax, 0xf00
0x0009    5d                pop rbp
0x000a    c3                ret 
```
And in a different syntax:
```
$ clad -S att '55 48 89 e5 b8 00 0f 00 00 5d c3' | column -s'|' -t
0x0000    55                pushq %rbp
0x0001    48 89 e5          movq %rsp, %rbp
0x0004    b8 00 0f 00 00    movl $0xf00, %eax
0x0009    5d                popq %rbp
0x000a    c3                retq 
```

### Overlapping instructions
The disassembly cares only about hex digits, so you can easily explore arbitrary
sequences. Here's an example of overlapping instructions:
```
$ clad '83 f0 04 04 90' | column -s'|' -t
0x0000    83 f0 04    xor eax, 4
0x0003    04 90       add al, 0x90

$ clad '!83 !f0 04 04 90' | column -s'|' -t
0x0000    04 04    add al, 4
0x0002    90       nop 
```

### Single byte instructions amd64
Here's how you can generate all valid single byte amd64 instructions:
```
$ echo {0..255} | tr ' ' '\n' | xargs -L1 printf "%02x\n" | xargs -L 1 clad -A x86 -M 64 2>&1 | grep '^0x0000' 
0x0000 | 50 | push rax
0x0000 | 51 | push rcx
0x0000 | 52 | push rdx
0x0000 | 53 | push rbx
0x0000 | 54 | push rsp
0x0000 | 55 | push rbp
0x0000 | 56 | push rsi
0x0000 | 57 | push rdi
0x0000 | 58 | pop rax
0x0000 | 59 | pop rcx
0x0000 | 5a | pop rdx
0x0000 | 5b | pop rbx
0x0000 | 5c | pop rsp
0x0000 | 5d | pop rbp
0x0000 | 5e | pop rsi
0x0000 | 5f | pop rdi
0x0000 | 6c | insb byte ptr [rdi], dx
0x0000 | 6d | insd dword ptr [rdi], dx
0x0000 | 6e | outsb dx, byte ptr [rsi]
0x0000 | 6f | outsd dx, dword ptr [rsi]
0x0000 | 90 | nop 
0x0000 | 91 | xchg eax, ecx
0x0000 | 92 | xchg eax, edx
0x0000 | 93 | xchg eax, ebx
0x0000 | 94 | xchg eax, esp
0x0000 | 95 | xchg eax, ebp
0x0000 | 96 | xchg eax, esi
0x0000 | 97 | xchg eax, edi
0x0000 | 98 | cwde 
0x0000 | 99 | cdq 
0x0000 | 9b | wait 
0x0000 | 9c | pushfq 
0x0000 | 9d | popfq 
0x0000 | 9e | sahf 
0x0000 | 9f | lahf 
0x0000 | a4 | movsb byte ptr [rdi], byte ptr [rsi]
0x0000 | a5 | movsd dword ptr [rdi], dword ptr [rsi]
0x0000 | a6 | cmpsb byte ptr [rsi], byte ptr [rdi]
0x0000 | a7 | cmpsd dword ptr [rsi], dword ptr [rdi]
0x0000 | aa | stosb byte ptr [rdi], al
0x0000 | ab | stosd dword ptr [rdi], eax
0x0000 | ac | lodsb al, byte ptr [rsi]
0x0000 | ad | lodsd eax, dword ptr [rsi]
0x0000 | ae | scasb al, byte ptr [rdi]
0x0000 | af | scasd eax, dword ptr [rdi]
0x0000 | c3 | ret 
0x0000 | c9 | leave 
0x0000 | cb | retf 
0x0000 | cc | int3 
0x0000 | cf | iretd 
0x0000 | d7 | xlatb 
0x0000 | ec | in al, dx
0x0000 | ed | in eax, dx
0x0000 | ee | out dx, al
0x0000 | ef | out dx, eax
0x0000 | f1 | int1 
0x0000 | f4 | hlt 
0x0000 | f5 | cmc 
0x0000 | f8 | clc 
0x0000 | f9 | stc 
0x0000 | fa | cli 
0x0000 | fb | sti 
0x0000 | fc | cld 
0x0000 | fd | std 
```
This is how you can see which single byte instructions are common to x86 and
amd64, and how many there are:
```
$ comm -12 <(echo {0..255} | tr ' ' '\n' | xargs -L1 printf "%02x\n" | xargs -L 1 clad -A x86 -M 64 2>&1 | grep '^0x0000' | sort) <(echo {0..255} | tr ' ' '\n' | xargs -L1 printf "%02x\n" | xargs -L 1 clad -A x86 -M 32 2>&1 | grep '^0x0000' | sort) | cat -n
     1  0x0000 | 90 | nop 
     2  0x0000 | 91 | xchg eax, ecx
     3  0x0000 | 92 | xchg eax, edx
     4  0x0000 | 93 | xchg eax, ebx
     5  0x0000 | 94 | xchg eax, esp
     6  0x0000 | 95 | xchg eax, ebp
     7  0x0000 | 96 | xchg eax, esi
     8  0x0000 | 97 | xchg eax, edi
     9  0x0000 | 98 | cwde 
    10  0x0000 | 99 | cdq 
    11  0x0000 | 9b | wait 
    12  0x0000 | 9e | sahf 
    13  0x0000 | 9f | lahf 
    14  0x0000 | c3 | ret 
    15  0x0000 | c9 | leave 
    16  0x0000 | cb | retf 
    17  0x0000 | cc | int3 
    18  0x0000 | cf | iretd 
    19  0x0000 | d7 | xlatb 
    20  0x0000 | ec | in al, dx
    21  0x0000 | ed | in eax, dx
    22  0x0000 | ee | out dx, al
    23  0x0000 | ef | out dx, eax
    24  0x0000 | f1 | int1 
    25  0x0000 | f4 | hlt 
    26  0x0000 | f5 | cmc 
    27  0x0000 | f8 | clc 
    28  0x0000 | f9 | stc 
    29  0x0000 | fa | cli 
    30  0x0000 | fb | sti 
    31  0x0000 | fc | cld 
    32  0x0000 | fd | std 
```

### All one byte + four byte argument instructions
Instructions like
```
jmp <dword>, call <dword>, push <dword>
```
etc. in amd64:
```
$ seq 0 255 | awk '{print sprintf("\"%02x 00 00 00 00\"", $0)}' | xargs -L1 clad 2>&1 | grep '^0x0000' | awk -F ' \\| ' '{a=$2; if (4 == gsub(" ", " ", a)) print $0}' | cat -n
     1  0x0000 | 05 00 00 00 00 | add eax, 0
     2  0x0000 | 0d 00 00 00 00 | or eax, 0
     3  0x0000 | 15 00 00 00 00 | adc eax, 0
     4  0x0000 | 1d 00 00 00 00 | sbb eax, 0
     5  0x0000 | 25 00 00 00 00 | and eax, 0
     6  0x0000 | 2d 00 00 00 00 | sub eax, 0
     7  0x0000 | 35 00 00 00 00 | xor eax, 0
     8  0x0000 | 3d 00 00 00 00 | cmp eax, 0
     9  0x0000 | 68 00 00 00 00 | push 0
    10  0x0000 | a9 00 00 00 00 | test eax, 0
    11  0x0000 | b8 00 00 00 00 | mov eax, 0
    12  0x0000 | b9 00 00 00 00 | mov ecx, 0
    13  0x0000 | ba 00 00 00 00 | mov edx, 0
    14  0x0000 | bb 00 00 00 00 | mov ebx, 0
    15  0x0000 | bc 00 00 00 00 | mov esp, 0
    16  0x0000 | bd 00 00 00 00 | mov ebp, 0
    17  0x0000 | be 00 00 00 00 | mov esi, 0
    18  0x0000 | bf 00 00 00 00 | mov edi, 0
    19  0x0000 | e8 00 00 00 00 | call 5
    20  0x0000 | e9 00 00 00 00 | jmp 5
```
All which are in 32 bit x86 but not in 64 bit:
```
$ comm -13 <(seq 0 255 | awk '{print sprintf("\"%02x 00 00 00 00\"", $0)}' | xargs -L1 clad -A x86 -M 64 2>&1 | grep '^0x0000' | awk -F ' \\| ' '{a=$2; if (4 == gsub(" ", " ", a)) print $0}' | sort) <(seq 0 255 | awk '{print sprintf("\"%02x 00 00 00 00\"", $0)}' | xargs -L1 clad -A x86 -M 32 2>&1 | grep '^0x0000' | awk -F ' \\| ' '{a=$2; if (4 == gsub(" ", " ", a)) print $0}' | sort) | cat -n
     1  0x0000 | a0 00 00 00 00 | mov al, byte ptr [0]
     2  0x0000 | a1 00 00 00 00 | mov eax, dword ptr [0]
     3  0x0000 | a2 00 00 00 00 | mov byte ptr [0], al
     4  0x0000 | a3 00 00 00 00 | mov dword ptr [0], eax
```

## How it works
Clad uses the Capstone engine for disassembly and the Keystone engine for
assembly, which on their hand support numerous architectures, modes, and
syntaxes. To simplify the build process, clad does not provide any of the source
code for these libraries, or any library binaries.

## How to build
Clad requires the user to build static Keystone and Capstone libraries and point
the compiler to them during compilation. Capstone and Keystone can be found here  
https://github.com/capstone-engine  
and here  
https://github.com/keystone-engine  
Their build processes are straightforward to follow. As an example, to develop
clad I cloned both repos in my ~/repos folder:
```
$ ls ~/repos
capstone  keystone
```
compiled the libraries, and to compile clad I'd run:
```
make clad LIB_CAPSTONE_INCL_DIR='~/repos/capstone/include' LIB_CAPSTONE_A='~/repos/capstone/libcapstone.a' LIB_KEYSTONE_INCL_DIR='~/repos/keystone/include' LIB_KEYSTONE_A='~/repos/keystone/build/llvm/lib/libkeystone.a'
```
from the clad directory where the makefile is. Or, for convenience:
```
$ cat make-clad-cmd.txt 
make clad LIB_CAPSTONE_INCL_DIR='~/repos/capstone/include' LIB_CAPSTONE_A='~/repos/capstone/libcapstone.a' LIB_KEYSTONE_INCL_DIR='~/repos/keystone/include' LIB_KEYSTONE_A='~/repos/keystone/build/llvm/lib/libkeystone.a'

$ cat make-clad-cmd.txt | bash
g++ -c src/main.c -o obj/main.o -I ./src -Wall -Wfatal-errors 
g++ -c src/parse-opts/parse_opts.c -o obj/parse_opts.o -I ./src -Wall -Wfatal-errors 
g++ -c src/err/err.c -o obj/err.o -I ./src -Wall -Wfatal-errors 
g++ -c src/disasm/disasm.c -o obj/disasm.o -I ./src -I ~/repos/capstone/include -Wall -Wfatal-errors 
g++ -c src/hex2bytes/hex2bytes.c -o obj/hex2bytes.o -I ./src -Wall -Wfatal-errors 
g++ -c src/asm/asm.c -o obj/asm.o -I ./src -I ~/repos/keystone/include -Wall -Wfatal-errors 
g++ -c src/asmsplit/asmsplit.c -o obj/asmsplit.o -I ./src -Wall -Wfatal-errors 
g++ obj/main.o obj/parse_opts.o obj/err.o obj/disasm.o obj/hex2bytes.o obj/asm.o obj/asmsplit.o -o bin/clad ~/repos/capstone/libcapstone.a ~/repos/keystone/build/llvm/lib/libkeystone.a -I ./src -Wall -Wfatal-errors 

$ ls bin/
clad
```

## Hack
```
$ tree -d clad/
clad/
├── bin # <-- compiled clad and internal tests go here
├── obj # <-- all intermediate object files go here
├── src
│   ├── asm       # <-- the Keystone driver module
│   ├── asmsplit  # <-- reads a Keystone asm string instruction by instruction 
│   ├── disasm    # <-- the Capstone driver module
│   ├── err       # <-- the error reporting component
│   ├── hex2bytes # <-- turns ascii hex digits into binary values
│   └── parse-opts
│       └── parse-opts-code-generator # <-- generates the cli parsing code
└── tests # <-- tests for asmsplit and hex2bytes

11 directories
```

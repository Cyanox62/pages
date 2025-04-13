# Removing Annoying Popups with Reverse Engineering

No one really likes popup advertisements in software. But for some reason, certain closed-source developers treat these popups like their precious relics, guarded with layers of protection and a palpable fear of tampering. I encountered a program that displayed a popup and opens a website on startup recently that caused me a minor enough inconvenience to take it personally.

So I fired up my debugger, rolled up my sleeves, and dove head-first into a mess of overly-complicated x86 assembly.

## Planning the Attack

To plan an attack on software we need to notice some trends or patterns to help us find a place to start. One key observation: the software only displayed the popup advertisements the *first* time you opened the software. This means a piece of information must be stored somewhere on disk, some little breadcrumb to let the program know, "Hey, the user's already seen this ad. Don't bug them again." 

So, the question became: **what changed after the first launch?**

The software came accompanied by a `.ini` file, a classic configuration storage format. When I first downloaded the program, it included this little snippet within the `.ini` file:

```ini
[Hashes]
0=8b4d9fce1a75e3b82df6ac4f7392e4d01c67b8a5e9f3c0d42a16b5f87e9c3a2d4b8f3c1d7e9a5b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7
```

After I had run the program for the first time, the snippet changed to this:

```ini
[Hashes]
0=8b4d9fce1a75e3b82df6ac4f7392e4d01c67b8a5e9f3c0d42a16b5f87e9c3a2d4b8f3c1d7e9a5b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7
1337=f2e4d6a8c0b2e4f6a8c0d2e4f6a8c0b2e4f6a8c0d2e4f6a8c0b2e4f6a8c0d2e4f6a8c0b2e4f6a8c0d2e4f6a8c0b2e4f6a8c0d2e4f6a8c0b2e4f6a8c0d2e4f6a8
```

A new hash was inserted!

And sure enough, removing that second hash caused the popup to return. This was our ticket into the program! Somewhere within this process is code that validates the hash within the `.ini` file. Our job is to find that code and tamper with it to convince the program that everything was perfectly valid, no matter the provided hash.

To crack this puzzle, we’ll need to speak x86 and get comfortable with the tools at our disposal.<br>
I’ll walk you through the key concepts and utilities we’ll be using to pull this off.

Once we're geared up, we'll break our next moves into a 4-step plan:
1. Identify our target module
2. Find where the hash is loaded into memory
3. Trace which instructions read and subsequently validate that memory region
4. Modify those instructions so the program always treats the hash as valid

Let's dive in.

## x86 Assembly

x86 assembly can be very daunting at first glance. But underneath all the arcane syntax, it boils down to a simple rule: instructions are executed one at a time, from top to bottom unless explicitly told to go elsewhere. One of the core concepts is the idea of **registers**. These registers can be thought of as the CPU's hands. If the CPU wants to do something with data, whether it be addition, subtraction, comparisons, etc., it must have that data in a register first. Unlike variables in high-level languages, registers are limited in number and can have special purposes, so you have to be careful about what you put where.

Let's take a look at some simple examples and compare them to high-level programming languages.
- `mov eax, 1` - This is like `int x = 1`. It moves the value of 1 into the register `eax`.
- `add eax, 2` - Like `x = x + 2` or `x += 2`. Simple math, done directly on registers.
- `cmp eax, 5` - This is a comparison like `if (eax == 5)`. It sets some internal flags the CPU uses in subsequent instructions to make decisions.

Now here's where things get interesting: **jumps**.
A jump lets the program change the order of execution by skipping to a different instruction elsewhere in the code.
- `jmp some_label` – An unconditional jump. It says, "Go here no matter what."
- `je some_label` – A conditional jump that stands for "jump if equal." It only jumps if the last `cmp` found the respective values to be equal, known by those internal CPU flags that were previously set.

There are other conditional jumps too (`jne`, `jg`, `jl`, etc.), each based on different comparison outcomes, but the core idea is the same: compare something, then decide whether to jump based on the result. You may also see `call` instructions, which for our purposes you can assume to mean the same as an unconditional jump.

All numerical values in x86 assembly are typically represented in hexadecimal (base 16), which uses digits 0–9 and letters A–F to represent values. Hexadecimal constants are often represented with the prefix `0x` when it may be ambiguous whether you're referring to a decimal or hexadecimal number.

## The Debugger

We will be exploring the program's assembly instructions with a **debugger**. A debugger is a piece of software that runs an executable and takes control over its execution. It grants the user control to step through the program line by line, examining registers, memory, and other key pieces of information as you go. Basically, it turns a running program into something you can poke, prod, and pause at will.

One of the most powerful features in a debugger is a breakpoint. A breakpoint is like a checkpoint. You place it on a specific instruction, and when the program reaches that point, the debugger freezes execution so you can take a closer look. This is incredibly useful for catching the exact moment when something changes or something important happens.

I'll be using [x32dbg](https://x64dbg.com/) for this attack, but any debugger will do.

## Step 1: Detective Work

With an understanding of x86 assembly and our tools established, we need to put on our detective badge. Most applications load many additional libraries (DLLs) at runtime, known as modules. We need to identify which module is the culprit causing the popup or website to open. 

The easiest way to go about finding our target module would be to scan all loaded modules for any strings that match either the website URL or the text displayed on the popup. This is typically possible because strings are often stored in a module's `.data` section, commonly in read-only memory segments. Unfortunately, this module is heavily obfuscated, with not only all strings being complete gibberish, but some other clever techniques we'll run into later. Let's just say the developers *really* didn't want you tampering with this module.

With nothing to go off, the best way to go about finding our target module is to identify something unique about what we're trying to find to avoid other noise throughout the program. As far as I know, this program doesn't have any other popup windows or website opens, so that's something we can use.

Let's consider the Windows functions that are commonly used for displaying popups:
- `user32.MessageBoxA()`       - ANSI (8-bit character) version
- `user32.MessageBoxW()`       - Wide character (UTF-16) version

And consider the Windows functions that are commonly used for opening websites:
- `shell32.ShellExecuteA()`    - ANSI (8-bit character) version
- `shell32.ShellExecuteW()`    - Wide character (UTF-16) version

Being that our target application is 32-bit, and 32-bit applications tend to use ANSI, a solid first guess would be `user32.MessageBoxA()` and `shell32.ShellExecuteA()`. Let's add a breakpoint to both of those functions and run the program to see if either of them hit.

This gets us a hit on `shell32.ShellExecuteA()`! The program paused execution right before this function executed.<br>
Let's inspect our registers and see what data is being held in them just prior to execution:
```asm
EAX     7630A5F0        <shell32.ShellExecuteA>
ESI     05A1FC70        "https://popup-website.com"
EDI     5B565830        pkgsh.5B565830
```

And there it is, our culprit. The website URL sitting in the `esi` register right before execution, with `pkgsh.dll` showing up in the `edi` register, a clear indication that the call originates from this module. As with any investigation, seeing the suspect's address in the call stack is all but confirmation that `pkgsh.dll` is the one we're after.

## Step 2: Sneaking Through Memory

Now that we’ve identified `pkgsh.dll` as the shady character behind our annoying popup, we need to think of a way to dig into it's memory habits and find where it stashed our hash.

Let's consider a logical approach: If this hash from the `.ini` file has to be loaded into memory at some point in order to be compared, there *must* be a read operation. Files are commonly read through the Windows API function `ReadFile`. So, let's slap a breakpoint on the `ReadFile` function and see if we catch any calls to it.

We get a hit! Then another hit! *...and many, many more hits after that.*

It becomes obvious that this process calls this function hundreds of times during its execution. This is quite common for programs with many modules or configuration files. How do we know which of the hundreds of calls to this function stems from our target location? Every time our debugger hits on the `ReadFile` breakpoint, we can take a peek at the **call stack**, a record of *how* the program got to where it is. If this `ReadFile` function call stemmed from our `pkgsh.dll` module, we should see it somewhere in the execution sequence within our call stack.

And sure enough, among the many hits, one stands out. We catch a `ReadFile` with `pkgsh.dll` right there in the stack. Bingo.

```asm
Callstack:                                                              Interpreted Flow:
------------------------------------------------------------            ------------------------------
Address   To         From        Size   Party    Function               [0218EBCC] pkgsh.105018
0218EB40  5B71A0F5   76D53730    44     User     kernel32.ReadFile         ↓ calls
0218EB84  5B71DACB   5B71A0F5    1C     User     pkgsh.10DCF5           [0218EBA0] pkgsh.1116CB
0218EBA0  5B711418   5B71DACB    2C     User     pkgsh.1116CB              ↓ calls
0218EBCC  5B711531   5B711418    48     User     pkgsh.105018           [0218EB84] pkgsh.10DCF5  
                                                                           ↓ calls  
                                                                        [0218EB40] kernel32.ReadFile
```

Stepping forward a few instructions, we find something interesting in the nearby code:

```asm
5B603CD1    test eax, eax                 ;  Checking if eax = 0
5B603CD3    je  5B603D28              ─┐  ;  Jumping if that condition succeeds
                                       │
5B603CD5    call 5B7F05D6              │  ;  If the condition fails, flow into the next block of code
5B603CDA    nop                        │  ;  Presumably some failure path
5B603CDB    mov  edx, eax              │
5B603CDD    lea  ecx, [ebp-90]         │
5B603CE3    call 5B601A90              │
5B603CE8    push eax                   │
5B603CE9    mov  edx, 5B776E8C         │  ;  Interesting line!!
5B603CEE    mov  byte ptr [ebp-4], 0E  │
5B603CF2    lea  ecx, [ebp-48]         │
5B603CF5    call 5B610A80              │
5B603CFA    add  esp, 4                │
5B603CFD    lea  ecx, [ebp-90]         │
5B603D03    call 5B60D860              │
5B603D08    push 10                    │
5B603D0A    push 5B776EB8              │
5B603D0F    lea  ecx, [ebp-48]         │
5B603D12    call 5B60D740              │
5B603D17    push eax                   │
5B603D18    push 0                     │
5B603D1A    push ebx                   │
5B603D1B    call 5B8ED148              │
5B603D20    push 0                     │
5B603D22    push eax                   │
5B603D23    ret                        │
                                       | 
5B603D28    push ecx                ◄──┘  ; Jump lands here if eax == 0
```

Let's zoom in on that interesting line from above:

```asm
5B603CE9 | mov edx, 5B776E8C
```

This line is moving the value at memory address `0x5B603CE9` into the `edx` register.<br>
If we take a peek at this address in the program's memory, we find this:

```
Address   Hex                                           ASCII
5B603CE9  46 61 69 6C 65 64 20 74 6F 20 6C 6F 61 64 20  Failed to load  
5B603CF9  2E 69 6E 69 2E 0A 45 72 72 6F 72 20 63 6F 64  .ini..Error cod
```

This line is loading a failure string, "Failed to load .ini", into the `edx` register. This, combined with the fact that this code conditionally runs based on the result of the prior `test` (another type of comparison) instruction, makes it highly likely that this code is testing if the file was properly read!

Due to the nature of assembly running from top to bottom, this demonstrates the importance of conditional branching. If the file was read properly, it'll **jump over** the code block that prints an error message. If the file read failed, it'll naturally flow into this code and display the error. Think of this concept like a large pit in your path. If the comparison fails, we walk straight into the pit of instructions that will display an error message. If the comparison succeeds, we jump over the pit, never see the error message, and continue on our merry way, none the wiser.

The fact that the error message code was jumped over likely means the file has been successfully read and thus inserted into memory.
***
Let's take a quick look down that pit to see another clever technique in play by the developers. You'll notice that within this failure path and throughout this executable is an abundance of `call` / `jmp` operations. This is known as **control flow obfuscation**. This is a technique where developers split up continuous instructions throughout the executable and throw in junk code that does nothing to throw off potential attackers.

```
Original Flow:                     Obfuscated Flow:
-----------------------            ---------------------
start → do_thing1()                start → part1_of_thing1()
      → do_thing2()                      → junk_code
      → exit                             → part2_of_thing1()
                                         → more_junk
                                         → part1_of_thing2()
                                         → even_more_junk
                                         → part2_of_thing2()
                                         → exit
```
***
Now that the hash is loaded into memory and we didn't fall into the trap door, we can follow its usages like a breadcrumb trail to find our hash validation.

## Step 3: Needle in a Haystack

To find our hash validation needle in this haystack of obfuscated instructions, let's recall a key fact: our hash that currently resides in memory must be accessed in order to be validated.

Just like we can breakpoint instructions, we can breakpoint memory addresses. Since we know our hash is currently stored in memory, we can search for it by string.<br>A scan for our target hash value shows it lives at the address `052A25E0`, which we can confirm with our debugger's memory table:

```
Address   Hex                                              ASCII            
052A25E0  66 32 65 34 64 36 61 38 63 30 62 32 65 34 66 36  f2e4d6a8c0b2e4f6
052A25F0  61 38 63 30 64 32 65 34 66 36 61 38 63 30 62 32  a8c0d2e4f6a8c0b2
052A2600  65 34 66 36 61 38 63 30 64 32 65 34 66 36 61 38  e4f6a8c0d2e4f6a8
052A2610  63 30 62 32 65 34 66 36 61 38 63 30 64 32 65 34  c0b2e4f6a8c0d2e4
052A2620  66 36 61 38 63 30 62 32 65 34 66 36 61 38 63 30  f6a8c0b2e4f6a8c0
052A2630  64 32 65 34 66 36 61 38 63 30 62 32 65 34 66 36  d2e4f6a8c0b2e4f6
052A2640  61 38 63 30 64 32 65 34 66 36 61 38 63 30 62 32  a8c0d2e4f6a8c0b2
052A2650  65 34 66 36 61 38 63 30 64 32 65 34 66 36 61 38  e4f6a8c0d2e4f6a8

Concatenated String: f2e4d6a8c0b2e4f6a8c0d2e4f6a8c0b2e4f6a8c0d2e4f6a8c0b2e4f6a8c0d2e4f6a8c0b2e4f6a8c0d2e4f6a8c0b2e4f6a8c0d2e4f6a8c0b2e4f6a8c0d2e4f6a8
```

Now let's add a "Memory Access" breakpoint on the first byte of this string, the top left byte in this table. This will break when any instructions read from this byte of memory, which should bring us to the beginning of our hash validation.

We got a hit on a small function accessing our hash! At this point, `eax` currently holds our hash value, which confirms this function read in our hash from memory.<br>
Let's take a closer look at what this is doing:

```asm
5B60E7B0    lea edx,[ecx+1]               ;  Set 'edx' to one byte past the start of the string
5B60E7B3    mov al,[ecx]           ◄──┐   ;  Load current byte (character) into the 'al' register
                                      │           ; ecx represents our current index in the string, starting at 0
5B60E7B5    inc ecx                   │   ;  Move to next character in preparation for the next loop
5B60E7B6    test al,al                │   ;  Check if current character in 'al' == 0   
                                      │           ; 0 represents a 'null terminator', which indicates the end of a string
5B60E7B8    jne 5B60E7B3            ──┘   ;  If our comparison failed, loop to the next character

                                          ;  If we make it to this point, we didn't jump back up
                                          ;  This indicates that we found the end of the string

5B60E7BA    sub ecx,edx                   ;  Subtract the starting point from the ending point (plus one) to get string length
5B60E7BC    mov eax,ecx                   ;  Store the length into 'eax'
5B60E7BE    ret                           ;  Done!
```

After taking the time to understand this function, we can see this is counting the length of our hash.<br>
Here is some equivalent pseudocode in a higher-level language:

```cpp
int ecx = 0
int edx = ecx + 1
while (hash.charAt(ecx) != 0) {
    ecx++
}
int length = ecx - edx
```

While it does access our hash, this isn't doing any sort of validation, so this is likely not what we're looking for. Let's skip to the next time the memory is accessed.

We got another hit! Here's the next spot the code accesses our hash:

```asm
5B707E92    mov esi,[esp+10]      ;  Loads the start of the hash into 'esi'
5B707E96    mov ecx,[esp+14]      ;  Loads the length of the hash into 'ecx'
5B707E9A    mov edi,[esp+C]       ;  Loads the end of the hash into 'edi'
5B707E9E    mov eax, ecx
5B707EA0    mov edx, ecx
5B707EA2    add eax, esi
5B707EA4    cmp edi, esi          ;  Bounds check: is the start before the end?
5B707EA6    jbe 5B707EB0          ;  If yes, don't jump and continue downwards

5B707EB0    cmp ecx, 0x20         ;  Is the length < 32?
5B707EB3    jb 5B707EC0           ;  Then jump to an error

5B707EB5    cmp ecx, 0x80         ;  Is the length >= 128?
5B707EB8    jae 5B707EC5          ;  Then jump to an error

5B707EBA    rep movsb             ;  Copy hash buffer from 'esi' to 'edi'
```

This appears to be copying our hash to a new location in memory.<br>
But this raises the question: **why?**

If we continue executing the program, we'll find that our original hash from address `052A25E0` is **never accessed again**. This suggests yet another obfuscation / anti-tampering technique: relocating important to throw off an attacker. As we can tell from the assembly above, the hash got copied to the address within `esi`.

No big deal, we'll just go to that location in memory:

```
Address   Hex                                              ASCII
04DA4FE8  66 32 65 34 64 36 61 38 63 30 62 32 65 34 66 36  f2e4d6a8c0b2e4f6  
04DA4FF8  61 38 63 30 64 32 65 34 66 36 61 38 63 30 62 32  a8c0d2e4f6a8c0b2  
04DA5008  65 34 66 36 61 38 63 30 64 32 65 34 66 36 61 38  e4f6a8c0d2e4f6a8  
04DA5018  63 30 62 32 65 34 66 36 61 38 63 30 64 32 65 34  c0b2e4f6a8c0d2e4  
04DA5028  66 36 61 38 63 30 62 32 65 34 66 36 61 38 63 30  f6a8c0b2e4f6a8c0  
04DA5038  64 32 65 34 66 36 61 38 63 30 62 32 65 34 66 36  d2e4f6a8c0b2e4f6  
04DA5048  61 38 63 30 64 32 65 34 66 36 61 38 63 30 62 32  a8c0d2e4f6a8c0b2  
04DA5058  65 34 66 36 61 38 63 30 64 32 65 34 66 36 61 38  e4f6a8c0d2e4f6a8  
```

And unsurprisingly, we find our hash right here, identical to the first one. We know what we're doing by this point, let's keep following the breadcrumb trail and breakpoint the first byte again on this new location to see when this memory is accessed.

The very first time this new memory location is accessed, we come across something very promising:

```asm
; Hash comparison loop
5B612590 | mov eax,dword ptr ds:[ecx]     ; Load 4 bytes from first hash
5B612592 | cmp eax,dword ptr ds:[edx]     ; Compare with 4 bytes from second hash
5B612594 | jne 5B6125D3                   ; If bytes don't match, jump to failure path
5B612596 | add ecx,4                      ; Move to next 4 bytes in first hash
5B612599 | add edx,4                      ; Move to next 4 bytes in second hash
5B61259C | sub esi,4                      ; Adjust remaining bytes to compare
5B61259F | jae 5B612590                   ; Loop if more 4-byte chunks to compare
5B6125A4 | je 5B6125DB                    ; Jump to success path

; Failure path - hashes don't match
5B6125D3 | sbb eax,eax
5B6125D5 | or eax,1                       ; Set EAX to 1 (failure)
5B6125D8 | pop esi
5B6125D9 | pop ebp
5B6125DA | ret                            ; Return with failure result

; Success path - hashes match
5B6125DB | xor eax,eax                    ; Set EAX to 0 (success)
5B6125DD | pop esi
5B6125DE | pop ebp
5B6125DF | ret                            ; Return with success result
```

This is a hash comparison function, exactly what we've been looking for!

What's clever here is the control flow: the main loop (`jae` at `5B61259F`) keeps the comparisons going as long as there are bytes left. After the loop ends, the final jump (`je` at `5B6125A4`) jumps to the success path only if we've matched everything exactly. If the final condition fails, the code naturally flows straight into the failure path.

Now that we've found our needle in the haystack, the more crucial piece of our puzzle is in place!<br>
Time to make it forget its true from false.

## Step 4: Confusing the Program

With the failure path identified, we need to think of how to exploit this code. One thought is to override how the hash comparison works, or even trace back how the hash we're comparing against is calculated. Both of these approaches would work, but taking a closer look, we have a clearly defined failure and success path that are quite similar. 

How about instead we just convince the failure path to impersonate its successful counterpart?

The only difference between the success path and the failure path are the first lines:
```asm
Failure path               Success path
-----------------------    -----------------------
5B6125D3 | sbb eax,eax     5B6125DB | xor eax,eax 
5B6125D5 | or eax,1

5B6125D8 | pop esi         5B6125DD | pop esi
5B6125D9 | pop ebp         5B6125DE | pop ebp
5B6125DA | ret             5B6125DF | ret
```
No reason to overcomplicate this, let's just modify the failure path to match the success path exactly. That way, the validation won't know right from wrong.

When modifying instructions, we need to be mindful of their size, something I've simplified in our assembly examples until now. In the binary world, each instruction occupies a specific number of bytes depending on both the instruction type and its parameters.
```asm
; Failure path (5 bytes total)
sbb eax, eax    ; 0x19 0xC0
or  eax, 1      ; 0x83 0xC8 0x01

; Success path (2 bytes total)
xor eax, eax    ; 0x33 0xC0
```
When modifying binaries, bytes cannot be added nor removed or the structure of the program will be compromised. Since the failure path needs 3 more bytes of total data than the success path, we can append 3 `nop`s after our changes. This instruction stands for "no operation" and takes 1 byte each, perfect to use for padding when needed.

```asm
(Modified) Failure path             Success path
--------------------------------    --------------------------------
5B6125D3 | xor eax,eax | 33 C0      5B6125DB | xor eax,eax | 33 C0 
5B6125D5 | nop         | 90
5B6125D6 | nop         | 90
5B6125D7 | nop         | 90  

5B6125D8 | pop esi     | 5E         5B6125DD | pop esi     | 5E
5B6125D9 | pop ebp     | 5D         5B6125DE | pop ebp     | 5D
5B6125DA | ret         | C3         5B6125DF | ret         | C3
```

Now let's let our program finish execution. The code will begin the hash check, fail the first 4-byte hash comparison, and jump to what it believes is the failure path at `5B6125D3`. But thanks to our handy work, the program has unknowingly leapt into what is now a perfect clone of the success path.

With that, we now have an application free from popups! No matter what value we input as the hash, the program will always jump to a success path, tricking the program into always accepting our hash and avoiding the popup. 

Now we just need to save our work! [x32dbg](https://x64dbg.com/) comes with a feature for patching a module, allowing you to simply save a copy of the loaded module with your modifications, or "patches".

So, let's give that a try...
```
+---------------------------------------+
|              SAVE FAILED              |
+---------------------------------------+
|                                       |
|  Cannot locate modified instructions  |
|  in source file.                      |
|                                       |
|  Error code: 0xE0074D2C               |
|  "Target memory not mapped to file"   |
|                                       |
+---------------------------------------+
```


<br><br>
... how do we save our changes?

## Step 5?: It's Never as Easy as It Looks

Unfortunately, saving this module isn't going to be that simple due to the final layer of obfuscation. This DLL is **self-unpacking**, meaning it contains compressed / encrypted data. When the module is loaded, it contains instructions to **dynamically unpack itself** into more instructions. 

To illustrate a quick example, here's how a section of memory changes after the unpacking:

```asm
Address      | Before (Obfuscated)        | After (Deobfuscated)                             
-------------|----------------------------|---------------------------------------------
5B60F7A0     | 00 00  -> add [eax], al    | 00 51 FF -> add byte ptr ds:[ecx-1], dl     
5B60F7A2     | 00 00  -> add [eax], al    | 75 08    -> jne 5B60F7AD          
5B60F7A4     | 00 00  -> add [eax], al    | 8B CE    -> mov ecx, esi                    
5B60F7A6     | 00 00  -> add [eax], al    | FF 75 0C -> push dword ptr ss:[ebp+0C]      
5B60F7A8     | 00 00  -> add [eax], al    | FF 75 FC -> push dword ptr ss:[ebp-4]       
5B60F7AA     | 00 00  -> add [eax], al    | FF 75 F8 -> push dword ptr ss:[ebp-8]       
5B60F7AC     | 00 00  -> add [eax], al    |                                             
5B60F7AE     | 00 00  -> add [eax], al    |                                             
5B60F7B0     | 00 00  -> add [eax], al    | E8 AB 0F 00 00 -> call 5B610760   
```

Due to how this self-unpacking DLL works, we face a unique challenge. The instructions we just modified **don't actually exist** in the file stored on disk. They're generated at runtime during the unpacking process. The self-unpacking instructions themselves are stored on disk, which means those instructions are the only ones we can permanently patch.

I was able to confirm that the module finishes unpacking all instructions before executing any unpacked instructions with the use of breakpoints. This grants us a very small window of time between when the instructions finish unpacking and the execution shifts to the unpacked, non-persistent instructions. Within this time period, we need to force the application to execute some custom assembly code that will **dynamically overwrite** the unpacked instructions before they execute.

As such, our first step is to find when the instructions finish unpacking. This can be easily done with the same breakpoint trick used in step 3 to find where our hash value in memory was accessed. This time, we'll find instructions in memory that have not yet been unpacked (like the ones in the example diagram above) and place a "Memory Write" breakpoint to let us know when they are overwritten by the unpacking code.

This worked as expected and found a very large loop within the DLLs disk-written code. It's incredibly complex due to the aforementioned control flow obfuscation, but we don't care about the details. We just want to know when it's done. To do this, I'll set a breakpoint somewhere in this unpacking function and loop until the breakpoint stops hitting. Once the breakpoint no longer hits, I can slowly step forward and observe the differences in control flow now that the code has fully unpacked.

This brings us to a section of code that hits both of our requirements:
```asm
5BBCEBAC | cmp eax,1000000              ;  Executed only after unpacking has completed
5BBCEBB1 | movsx eax,di               
5BBCEBB4 | cmove eax,ebp                
5BBCEBB7 | mov eax,dword ptr ss:[ebp-8] 
5BBCEBBA | jmp 5B1F07F9
```
1. It is within the disk written instructions, allowing it to be persistently modified
2. It executes prior to the non-persistent hash validation instructions

To understand how we can use this, let's also introduce two new concepts:
1. **Code Cave** - An unused space in the module where we can safely insert our own code without overwriting important instructions.
2. **Trampoline Hook** - Overwriting an existing jump instruction to divert execution to our code cave, followed by jumping to the original location after our instructions execute.

Looking back at the code block above, that unconditional jump instruction is the perfect candidate for our trampoline hook. Since it's already jumping somewhere else (`5B1F07F9`), we can modify it to jump to our code cave to execute some custom instructions instead. We'll need to remember that original destination address though. After our code cave does its work, we'll want to jump back to where the program originally intended to go.

With our hook location identified, let's find a place where we can create a code cave. Luckily, at the very bottom of the memory space of this module, there's roughly 500 empty instructions that exist on disk.

```asm
5B59E8C1 | add byte ptr ds:[eax],al 
5B59E8C3 | add byte ptr ds:[eax],al 
5B59E8C5 | add byte ptr ds:[eax],al 
5B59E8C7 | add byte ptr ds:[eax],al 
5B59E8C9 | add byte ptr ds:[eax],al 
5B59E8CB | add byte ptr ds:[eax],al 
5B59E8CD | add byte ptr ds:[eax],al 
...
```

This is a perfect spot for our code cave. Let's grab the first address, `5B59E8C1`, and use that as our entry point.<br>
Let's also quickly go back to that code block from earlier with the unconditional jump and apply the first half of our trampoline hook.
```asm
5B41EBAC | cmp eax,1000000              ;  Executed only after unpacking has completed
5B41EBB1 | movsx eax,di               
5B41EBB4 | cmove eax,ebp                
5B41EBB7 | mov eax,dword ptr ss:[ebp-8] 
5B41EBBA | jmp 5B59E8C1                 ;  Jump to the address of our code cave!
```

With the first half of the hook in place, it's time to start writing our custom instructions into the code cave for us to execute after jumping there.

Hang onto your hats, this will get a bit bumpy.

***

Let's review our main goal here, which boils down to executing these three instructions:
```asm
mov word ptr ds:[base_address+125D3],C033
mov word ptr ds:[base_address+125D5],9090
mov byte ptr ds:[base_address+125D7],90 
``` 

These instructions are simply performing the exact same overwrite on the failure path that we previously did manually. Just like in step 4, we overwrote the differing 5 bytes of instructions in the failure path with the 2 byte instruction from the success path, followed by 3 `nop`s, which are represented by `0x90` in hex.

`125D3`, `125D5`, and `125D7` are the respective offsets where we can find those validation instructions in this module. That offset will always be static relative to the module position, but the module itself doesn't always load in the same position in memory. This is due to a security mechanism known as Address Space Layout Randomization (ASLR). The location the module loads into memory space is known as the **base address** of the module.

Here's a visualization:

```c
+----------------------+   +----------------------+   +----------------------+
|  Module Loaded at    |   |  Module Loaded at    |   |  Module Loaded at    |
|     0x50000000       |   |     0x63000000       |   |     0x7A200000       |
+----------------------+   +----------------------+   +----------------------+
|   Target Location:   |   |   Target Location:   |   |   Target Location:   |
|      0x50125D3       |   |      0x63125D3       |   |      0x7A325D3       |
|                      |   |                      |   |                      |
|    Derived Offset:   |   |    Derived Offset:   |   |    Derived Offset:   |
|       0x125D3        |   |       0x125D3        |   |       0x125D3        |
+----------------------+   +----------------------+   +----------------------+
```

Notice how although the base address changes across executions, the offset always remains the same. This makes the formula to calculate the location we need to write in any execution `base_address + offset`, as can be seen in the `mov` instructions above.

Consequently, before we can do these writes, we need to dynamically get the base address of the `pkgsh.dll` module in memory. We can do this by using the Process Environment Block (PEB) within this process. This is a data structure that contains information about a running process, including the loaded modules and their respective base addresses. In order to access each respective module, we have to access a few sub-modules of the PEB first.

To better illustrate this, consider a set of predefined rules:
- A -> B
- B -> C
- C -> D

In this example, if you have A you can get to B, if you have B you can get to C, etc.

Let's further imagine:
- We currently reside in letter A
- The structure we need in order to access any module's name and base address resides in letter D

We need three instructions to take our three "steps" deeper into these different structures to find the structure we need. Note that during these steps, we'll continuously overwrite `eax` with the value in our next step since we won't need that old reference anymore.

Let's start by accessing the PEB, which can always be accessed through the segment register `fs` at a static offset of `0x30` in a 32-bit process. 
```asm
mov eax, dword ptr fs:[30] ;  A -> B
```

Within the PEB, we access the `PEB_LDR_DATA` structure through offset `0xC`.
```asm
mov eax, dword ptr ds:[eax+C] ;  B -> C
```

Within `PEB_LDR_DATA`, can access the `InMemoryOrderModuleList` structure through offset `0x14`.
```asm
mov eax, dword ptr ds:[eax+14] ;  C -> D
```

We've now reached the `InMemoryOrderModuleList` structure, which contians information about every loaded module, including their base address and full name.

***

You'll notice at this point that I'm using seemingly random hex offsets to find the information we're looking for in the above instructions. These offsets are gathered through an understanding of various internal Windows data structures. Let's demonstrate this by walking through how the offset of `0x14` was identified to find the `InMemoryOrderModuleList` structure within the `PEB_LDR_DATA` structure in the above instruction.

[As defined by Windows](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data), here is the `PEB_LDR_DATA` data structure:
```c
typedef struct _PEB_LDR_DATA {       // Offset   Size
 BYTE       Reserved1[8];            // 0x00   | 8 bytes
 PVOID      Reserved2[3];            // 0x08   | 12 bytes (3 pointers * 4 bytes each on 32-bit)
 LIST_ENTRY InMemoryOrderModuleList; // 0x14   | 8 bytes (2 pointers * 4 bytes each on 32-bit)
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

`eax` currently represents the beginning of this structure, which is contiguous in memory. As such, we can take offsets from the beginning to access any individual member within this structure. If we examine the sizes of each member within this structure from top to bottom, we see that `InMemoryOrderModuleList` is a total of 28 bytes from the beginning of the structure, which converts to `0x14` in hex. This means we can take the beginning of the structure `eax` and add `0x14` to it to access `InMemoryOrderModuleList`.

***

A this point we have access to `InMemoryOrderModuleList`, which contains a list of all modules. Information about each module can be accessed via offsets the same way we did above. We currently have a reference to the very first module in the list.

Given any module in the list, let's note down three important offsets:
1. The module's full name = `0x28`
2. The module's base address = `0x10`
3. The next module in the list = `0x0`

Now that we understand how to get our module base address, let's start constructing formal assembly.

Our first step will be taking the same sequential steps as above to find the `InMemoryOrderModuleList` structure and store it in `eax`:
```asm
mov eax, dword ptr fs:[30]      ;  A -> B (Getting PEB)
mov eax, dword ptr ds:[eax+C]   ;  B -> C (Getting PEB_LDR_DATA)
mov eax, dword ptr ds:[eax+14]  ;  C -> D (Getting InMemoryOrderModuleList)
```

Now we can define a loop. For each module, we'll grab it's full name and then use comparisons to check if this is the right module.
```asm
mov esi,dword ptr ds:[eax+28]    ;  Store the module's full name in 'esi' (offset 0x28)

cmp word ptr ds:[esi],70         ;  Check if the first letter is 'p' (0x70 in hex)
jne failure                      ;  If it isn't, jump to failure path

cmp word ptr ds:[esi+2],67       ;  Check if the second letter is 'g' (0x67 in hex)
jne failure                      ;  If it isn't, jump to failure path

cmp word ptr ds:[esi+4],6B       ;  Check if the third letter is 'k' (0x6B in hex)
jne failure                      ;  If it isn't, jump to failure path

cmp word ptr ds:[esi+6],73       ;  Check if the fourth letter is 's' (0x73 in hex)
jne failure                      ;  If it isn't, jump to failure path

cmp word ptr ds:[esi+6],68       ;  Check if the fifth letter is 'h' (0x68 in hex)
jne failure                      ;  If it isn't, jump to failure path
```

If all of these checks pass and we never hit a jump, we can flow right into our success path:
```asm
mov ebx,dword ptr ds:[eax+10]    ;  Store the module's base address in 'ebx' (offset 0x10)
```

And finally, if we fail any checks, we need to define our failure path:
```asm
mov eax,dword ptr ds:[eax]       ;  Load the next module into 'eax' (offset 0x0, or just 'eax')
test eax,eax                     ;  Check if we've hit the end of the list
jne loop                         ;  If we haven't hit the end, jump back to the top of the loop
```

With all our pieces ready, let's fill in our jump addresses, add in our code to find the base address, and finally the code to make our instruction modifications:
```asm
5B59E8C1 | pushad                             ;  Maintains register integrity
5B59E8C2 | pushfd                             ;  Maintains flag integrity

; Fetching module list
5B59E8C3 | mov eax,dword ptr fs:[30]          ;  Fetching InMemoryOrderModuleList
5B59E8C9 | mov eax,dword ptr ds:[eax+C]    
5B59E8CC | mov eax,dword ptr ds:[eax+14]   

; Checking if we found our target module
5B59E8D0 | mov esi,dword ptr ds:[eax+28]      ;  Comparison loop
5B59E8D3 | cmp word ptr ds:[esi],4F        
5B59E8D7 | jne 5B59E8F5                       ;  Jump to failure path         
5B59E8D9 | cmp word ptr ds:[esi+2],6E      
5B59E8DE | jne 5B59E8F5                       ;  Jump to failure path     
5B59E8E0 | cmp word ptr ds:[esi+4],6C      
5B59E8E5 | jne 5B59E8F5                       ;  Jump to failure path     
5B59E8E7 | cmp word ptr ds:[esi+6],69      
5B59E8EC | jne 5B59E8F5                       ;  Jump to failure path       

; Success path
5B59E8EF | mov ebx,dword ptr ds:[eax+10]      ;  Stores the module base address in 'ebx'
5B59E8F2 | jmp 5B59E8FB                       ;  Jump over failure path!

; Failure path
5B59E8F5 | mov eax,dword ptr ds:[eax]         ;  Moves to the next module
5B59E8F7 | test eax,eax                       ;  Tests if we have another module to check
5B59E8F9 | jne 5B59E8D0                       ;  Jumps back to the top of the loop

; Overwriting hash validation
5B59E8FB | mov word ptr ds:[ebx+125D3],C033   ;  Now we have the module's base address in 'ebx'
5B59E904 | mov word ptr ds:[ebx+125D5],9090   ;  We can use the base address with our offsets from earlier to overwrite the instructions!
5B59E90D | mov byte ptr ds:[ebx+125D7],90

5B59E914 | popfd                              ;  Restores flag integrity
5B59E915 | popad                              ;  Restores register integrity

; Second half of trampoline hook
5B59E916 | jmp 5B1F07F9                       ;  The original location our unconditional jump was supposed to jump to
```

Notice that at the end of this function, we jump back to the *original address* that our unconditional jump was initially intended to reach. This completes the trampoline hook!

And that's it! Let's do a quick recap of what changes we've made and how they'll affect subsequent execution:
1. When the module finishes unpacking its instructions, it'll jump to our code cave instead of the intended location
2. Our code cave executes, finding the base address of the target module and using it to overwrite the instructions that cause a failed hash validation
3. Our trampoline hook finishes the process by jumping back to the original intended location, allowing execution to finish normally

Let's now finally save our module by applying our patches:
```
+---------------------------------+
|        Patch Successful!        |
+---------------------------------+
|                                 |
|      84/84 patches applied      |
|                                 |
+---------------------------------+
```

Now that we've patched the instructions that exist on disk, our changes are permanent. The next time the program runs, whether it's on our machine or someone else's, it'll behave exactly as we've modified it. It dynamically modifies the hash validation code, and the popup is gone for good.

From here on out, it's smooth sailing.

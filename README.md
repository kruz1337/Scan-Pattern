# Scan-Pattern
This repository contains source code that you can easily implement to your project for scanning patterns easily in windows.

![](https://img.shields.io/badge/license-GNU-green?style=plastic) ![Platform](https://img.shields.io/badge/platform-Windows-blue?style=plastic)

![](https://raw.githubusercontent.com/kruz1337/Scan-Pattern/main/thumbnail.gif)

## What is Pattern Scaning?
When a software is compiled on a device, it stores binary codes, these binary codes store machine codes and you can see machine codes by using disassemblers like `IDA, GHidra, x64dbg, Cheat Engine`. 
Each variable and function has addresses on memory, offsets are used to find these addresses, you can also find these offsets by analyzing the code with a disassembler but these offsets are relative, so they can change with every software update or memory cleanup. That's why we use Patterns to automatically find the offsets.

## How is Pattern Scanning works?
To find your offset you need to have byte arrays, these byte arrays can have wildcards. These byte arrays can be created using the disassembler. Memory is read byte by byte and each byte is compared and in this process wildcards are skipped in each search because wildcards are relative bytes that can be variable. Wildcards are represented as single or multiple question marks.

## Example for using Scan-Pattern?
```c++
unsigned long outOffset;

// External scan with byte array:
ScanPattern::ScanPattern(&outOffset, "Process.exe", "Module.dll", "05 ? ? ? ? 83 D2 ? 0F AC D0");

// Internal scan with byte array:
ScanPattern::ScanPattern(&outOffset, "Module.dll", "05 ? ? ? ? 83 D2 ? 0F AC D0");

// External scan with byte string:
ScanPattern::ScanPatternString(&outOffset, "Process.exe", "Module.dll", "\x05\x00\x00\x00\x00\x83\xD2\x00\x0F\xAC\xD0", "x????xx?xxx");

// Internal scan with byte string:
ScanPattern::ScanPatternString(&outOffset, "Module.dll", "\x05\x00\x00\x00\x00\x83\xD2\x00\x0F\xAC\xD0", "x????xx?xxx");
```

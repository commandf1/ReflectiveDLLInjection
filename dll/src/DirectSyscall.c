#include "DirectSyscall.h"

#pragma optimize("g", off)
#ifdef __MINGW32__
#pragma GCC push_options
#pragma GCC optimize("O0")
#endif

#pragma warning(disable : 4100) // Unreferenced parameter 'pSyscall' is intentionally handled by assembly.
NTSTATUS SyscallStub(Syscall *pSyscall, ...)
{
	// This function acts as a bridge to the assembly trampoline. The first argument,
	// pSyscall, is passed in the first argument register (rcx/x0/stack), and all
	// subsequent arguments follow the standard C calling convention.
	return DoSyscall();
}
#pragma warning(default : 4100)

NTSTATUS rdiNtAllocateVirtualMemory(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, ULONG_PTR pZeroBits, PSIZE_T pRegionSize, ULONG ulAllocationType, ULONG ulProtect)
{
	return SyscallStub(pSyscall, hProcess, pBaseAddress, pZeroBits, pRegionSize, ulAllocationType, ulProtect);
}
NTSTATUS rdiNtProtectVirtualMemory(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, PSIZE_T pNumberOfBytesToProtect, ULONG ulNewAccessProtection, PULONG ulOldAccessProtection)
{
	return SyscallStub(pSyscall, hProcess, pBaseAddress, pNumberOfBytesToProtect, ulNewAccessProtection, ulOldAccessProtection);
}
NTSTATUS rdiNtFlushInstructionCache(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, SIZE_T FlushSize)
{
	return SyscallStub(pSyscall, hProcess, pBaseAddress, FlushSize);
}
NTSTATUS rdiNtLockVirtualMemory(Syscall *pSyscall, HANDLE hProcess, PVOID *pBaseAddress, PSIZE_T NumberOfBytesToLock, ULONG MapType)
{
	return SyscallStub(pSyscall, hProcess, pBaseAddress, NumberOfBytesToLock, MapType);
}

#ifdef __MINGW32__
#pragma GCC pop_options
#endif
#pragma optimize("g", on)

//===============================================================================================//
// This function resolves the necessary information for direct syscall invocation. It uses
// a hybrid strategy.
//
// The core premise for all platforms is "Hell's Gate": sorting ntdll's Zw* exports by their
// memory address gives their true syscall number, which is the number the kernel expects.
//
// The verification and stub-finding logic then differs per platform:
//   - x86/x64: The function stubs are predictable. The 'syscall; ret' gadget used for
//     execution is at a fixed offset from the function's start, allowing for reliable
//     hook bypass.
//
//   - ARM64: On modern Windows, the function stubs are not simple wrappers around a generic
//     'svc #0'. Instead, the syscall number is encoded directly into the 'svc #<imm>'
//     instruction itself. This function uses a reverse-engineered formula to predict the
//     exact opcode of a given function's 'svc' instruction, verifying its integrity.
//     The "stub" we execute is the function address itself.
//===============================================================================================//
BOOL getSyscalls(PVOID pNtdllBase, Syscall *Syscalls[], DWORD dwSyscallSize)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pNtdllBase;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pdwAddrOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfFunctions);
	PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNames);
	PWORD pwAddrOfNameOrdinales = (PWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNameOrdinals);

	SYSCALL_LIST SyscallList;
	SyscallList.dwCount = 0;

	// STEP 1: Enumerate all functions exported from ntdll.dll that begin with "Zw".
	// Store their hash and address in a temporary list.
	for (DWORD dwIdxfName = 0; dwIdxfName < pExportDir->NumberOfNames; dwIdxfName++)
	{
		PCHAR FunctionName = (PCHAR)((PBYTE)pNtdllBase + pdwAddrOfNames[dwIdxfName]);
		if (*(USHORT *)FunctionName == 0x775a) // "Zw" in little-endian
		{
			if (SyscallList.dwCount >= MAX_SYSCALLS)
				break;
			SyscallList.Entries[SyscallList.dwCount].dwCryptedHash = _hash(FunctionName);
			SyscallList.Entries[SyscallList.dwCount].pAddress = (PVOID)((PBYTE)pNtdllBase + pdwAddrOfFunctions[pwAddrOfNameOrdinales[dwIdxfName]]);
			SyscallList.dwCount++;
		}
	}

	// STEP 2: Sort the list of Zw* functions by their memory address.
	// The index of a function in this sorted list is its true syscall number.
	for (DWORD i = 0; i < SyscallList.dwCount - 1; i++)
	{
		for (DWORD j = 0; j < SyscallList.dwCount - i - 1; j++)
		{
			if (SyscallList.Entries[j].pAddress > SyscallList.Entries[j + 1].pAddress)
			{
				SYSCALL_ENTRY TempEntry = SyscallList.Entries[j];
				SyscallList.Entries[j] = SyscallList.Entries[j + 1];
				SyscallList.Entries[j + 1] = TempEntry;
			}
		}
	}

	// STEP 3: Find the syscalls required by our loader and populate their structs.
	for (DWORD dwIdxSyscall = 0; dwIdxSyscall < dwSyscallSize; ++dwIdxSyscall)
	{
		for (DWORD i = 0; i < SyscallList.dwCount; ++i)
		{
			if (SyscallList.Entries[i].dwCryptedHash == Syscalls[dwIdxSyscall]->dwCryptedHash)
			{
				// The function's index 'i' in the sorted list is the syscall number.
				Syscalls[dwIdxSyscall]->dwSyscallNr = i;

#if defined(_M_ARM64)
				// For ARM64, verify the function stub's opcode. Based on reverse engineering,
				// the opcode for an unhooked 'svc' instruction can be predicted:
				DWORD expectedOpcode = 0xd4000001 + (i * 0x20);
				if (*(PDWORD)SyscallList.Entries[i].pAddress == expectedOpcode)
				{
					// The "stub" our assembly will call is the function itself, as it
					// already contains the correctly encoded 'svc' instruction.
					Syscalls[dwIdxSyscall]->pStub = SyscallList.Entries[i].pAddress;
				}
#else
// For x86/x64, the "stub" is a pointer to the 'syscall; ret' gadget
// inside the function, which is at a predictable offset.
#if defined(_M_X64)
				Syscalls[dwIdxSyscall]->pStub = (PVOID)((PBYTE)SyscallList.Entries[i].pAddress + 8);
#else // _M_IX86
				Syscalls[dwIdxSyscall]->pStub = (PVOID)((PBYTE)SyscallList.Entries[i].pAddress + 5);
#endif
#endif
				break; // Found our function, move to the next required syscall.
			}
		}
	}

	// Final validation to ensure all required syscalls were successfully found and verified.
	for (DWORD i = 0; i < dwSyscallSize; ++i)
	{
		if (Syscalls[i]->pStub == NULL)
			return FALSE;
	}

	return TRUE;
}
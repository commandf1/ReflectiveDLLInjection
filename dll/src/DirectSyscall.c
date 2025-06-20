#include "DirectSyscall.h"

#pragma optimize("g", off)
#ifdef __MINGW32__
#pragma GCC push_options
#pragma GCC optimize("O0")
#endif

#pragma warning(disable : 4100) // Unreferenced parameter 'pSyscall' is handled by assembly.
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

// Scans a region of memory for a specific byte pattern (gadget).
// This is used on ARM64 to find a generic syscall execution gadget.
static PVOID FindGadget(PBYTE pCodeBase, ULONG ulCodeSize, const PBYTE pGadgetSignature, ULONG ulGadgetSize)
{
	if (!pCodeBase || ulCodeSize == 0 || !pGadgetSignature || ulGadgetSize == 0)
		return NULL;

	for (ULONG i = 0; i <= ulCodeSize - ulGadgetSize; ++i)
	{
		BOOL bFound = TRUE;
		for (ULONG j = 0; j < ulGadgetSize; ++j)
		{
			if (pCodeBase[i + j] != pGadgetSignature[j])
			{
				bFound = FALSE;
				break;
			}
		}
		if (bFound)
		{
			return (PVOID)(pCodeBase + i);
		}
	}
	return NULL;
}

//===============================================================================================//
// GETSYSCALLS
//
// This function is the core of the dynamic syscall resolution mechanism. It populates an
// array of 'Syscall' structures with the necessary information to perform direct syscalls,
// bypassing user-land API hooks.
//
// The technique, known as "Hell's Gate", relies on the observation that the syscall numbers
// for ntdll's Zw* functions correspond to their memory address order.
//
// For ARM64, this technique is modified. The individual Zw* function stubs are inconsistent.
// Instead, we use the sorting method to get the correct syscall number but find a single,
// generic "svc #0; ret" gadget within ntdll's code that we can reuse for all syscalls.
//===============================================================================================//
BOOL getSyscalls(PVOID pNtdllBase, Syscall *Syscalls[], DWORD dwSyscallSize)
{
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pNtdllBase;
	PIMAGE_NT_HEADERS pNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHdr->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pdwAddrOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfFunctions);
	PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNames);
	PWORD pwAddrOfNameOrdinales = (PWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNameOrdinals);

	PVOID pSyscallGadget = NULL;

#if defined(_M_ARM64)
	// On ARM64, we hunt for a generic gadget to execute our syscalls. The pattern
	// "svc #0; ret" is ideal. Its byte signature is { 0x01, 0x00, 0x00, 0xD4, 0xC0, 0x03, 0x5F, 0xD6 }.
	const BYTE svc_ret_gadget[] = {0x01, 0x00, 0x00, 0xD4, 0xC0, 0x03, 0x5F, 0xD6};
	pSyscallGadget = FindGadget((PBYTE)pNtdllBase, pNtHdrs->OptionalHeader.SizeOfImage, svc_ret_gadget, sizeof(svc_ret_gadget));
	if (!pSyscallGadget)
	{
		return FALSE; // Cannot proceed without a valid syscall gadget.
	}
#endif

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
	// The index of a function in this sorted list is its syscall number.
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

	// STEP 3: Find the syscalls required by our loader. For each one, store its
	// syscall number (its index 'i') and the address of the syscall execution stub.
	for (DWORD dwIdxSyscall = 0; dwIdxSyscall < dwSyscallSize; ++dwIdxSyscall)
	{
		BOOL bFound = FALSE;
		for (DWORD i = 0; i < SyscallList.dwCount; ++i)
		{
			if (SyscallList.Entries[i].dwCryptedHash == Syscalls[dwIdxSyscall]->dwCryptedHash)
			{
				Syscalls[dwIdxSyscall]->dwSyscallNr = i;

#if defined(_M_ARM64)
				// On ARM64, we use the single, generic gadget we found earlier.
				Syscalls[dwIdxSyscall]->pStub = pSyscallGadget;
#else
// On x86/x64, the syscall gadget is at a predictable offset from the function's start.
// This offset is where the 'syscall; ret' instructions reside, bypassing any hook.
#if defined(_M_X64)
				Syscalls[dwIdxSyscall]->pStub = (PVOID)((PBYTE)SyscallList.Entries[i].pAddress + 8);
#else // _M_IX86
				Syscalls[dwIdxSyscall]->pStub = (PVOID)((PBYTE)SyscallList.Entries[i].pAddress + 5);
#endif
#endif
				bFound = TRUE;
				break;
			}
		}
		if (!bFound)
		{
			return FALSE; // A required syscall was not found in ntdll.
		}
	}

	// Final validation to ensure all syscall stubs were successfully resolved.
	for (DWORD i = 0; i < dwSyscallSize; ++i)
	{
		if (Syscalls[i]->pStub == NULL)
			return FALSE;
	}

	return TRUE;
}

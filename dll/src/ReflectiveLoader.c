//===============================================================================================//
// Copyright (c) 2013, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted
// provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice, this list of
// conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright notice, this list of
// conditions and the following disclaimer in the documentation and/or other materials provided
// with the distribution.
//
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include "DirectSyscall.c"

HINSTANCE hAppInstance = NULL;

#ifdef __MINGW32__
#define WIN_GET_CALLER() __builtin_extract_return_addr(__builtin_return_address(0))
#else
#pragma intrinsic(_ReturnAddress)
#define WIN_GET_CALLER() _ReturnAddress()
#endif
// This function can not be inlined by the compiler, ensuring we get the address of the
// instruction that called into the loader, which is critical for finding our own image base.
__declspec(noinline) ULONG_PTR caller(VOID)
{
	return (ULONG_PTR)WIN_GET_CALLER();
}
//===============================================================================================//
#ifdef RDIDLL_NOEXPORT
#define RDIDLLEXPORT
#else
#define RDIDLLEXPORT DLLEXPORT
#endif

//===============================================================================================//
//                                     INTERNAL DEBUGGING CODES                                  //
//===============================================================================================//
#define RDI_ERR_BASE 0xE0000000
#define RDI_ERR_FIND_IMAGE_BASE (RDI_ERR_BASE | 0x1000)
#define RDI_ERR_RESOLVE_DEPS (RDI_ERR_BASE | 0x2000) // Generic dependency failure
#define RDI_ERR_ALLOC_MEM (RDI_ERR_BASE | 0x3000)
// Granular codes for dependency resolution:
#define RDI_ERR_NO_KERNEL32 (RDI_ERR_BASE | 0x2100)		 // Failed to find kernel32.dll by hash
#define RDI_ERR_NO_NTDLL (RDI_ERR_BASE | 0x2200)		 // Failed to find ntdll.dll by hash
#define RDI_ERR_NO_EXPORTS (RDI_ERR_BASE | 0x2300)		 // Found kernel32, but couldn't find required exports
#define RDI_ERR_GETSYSCALLS_FAIL (RDI_ERR_BASE | 0x2400) // getSyscalls() failed

// Helper to return a unique error code, making remote debugging possible.
static ULONG_PTR _report_and_exit(DWORD dwErrorCode)
{
	return dwErrorCode;
}

//===============================================================================================//
//                                      INTERNAL LOADER CONTEXT                                  //
//===============================================================================================//
// A context structure to hold all state for the loader, improving readability.
typedef struct
{
	ULONG_PTR uiLibraryAddress;
	ULONG_PTR uiBaseAddress;
	PIMAGE_NT_HEADERS pNtHeaders;
	LOADLIBRARYA pLoadLibraryA;
	GETPROCADDRESS pGetProcAddress;
	PVOID pNtdllBase;
	Syscall ZwAllocateVirtualMemorySyscall;
	Syscall ZwProtectVirtualMemorySyscall;
	Syscall ZwFlushInstructionCacheSyscall;
#ifdef ENABLE_STOPPAGING
	Syscall ZwLockVirtualMemorySyscall;
#endif
} LOADER_CONTEXT, *PLOADER_CONTEXT;

//===============================================================================================//
//                                    INTERNAL HELPER FUNCTIONS                                  //
//===============================================================================================//
// STEP 0: Finds the loader's own image base in memory by searching backwards from the caller's address.
static ULONG_PTR _find_image_base(VOID)
{
	ULONG_PTR uiLibraryAddress = caller();
	while (TRUE)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)uiLibraryAddress;
		if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
		{
			ULONG_PTR uiHeaderValue = pDosHeader->e_lfanew;
			// Sanity check the e_lfanew value to avoid problems with bogus PE signatures.
			if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
			{
				if (((PIMAGE_NT_HEADERS)(uiLibraryAddress + uiHeaderValue))->Signature == IMAGE_NT_SIGNATURE)
					return uiLibraryAddress;
			}
		}
		uiLibraryAddress--;
	}
}

// STEP 1: Resolves all required functions and prepares for direct syscalls.
static ULONG_PTR _resolve_dependencies(PLOADER_CONTEXT pContext)
{
	ULONG_PTR uiBaseAddress;
	ULONG_PTR uiValueA, uiValueB, uiValueC;
	USHORT usCounter;
	DWORD dwHashValue;
	ULONG_PTR uiExportDir, uiNameArray;
	BOOL bFoundKernel32 = FALSE;
	BOOL bFoundNtdll = FALSE;

#ifdef ENABLE_STOPPAGING
	Syscall *Syscalls[] = {&pContext->ZwAllocateVirtualMemorySyscall, &pContext->ZwProtectVirtualMemorySyscall, &pContext->ZwFlushInstructionCacheSyscall, &pContext->ZwLockVirtualMemorySyscall};
#else
	Syscall *Syscalls[] = {&pContext->ZwAllocateVirtualMemorySyscall, &pContext->ZwProtectVirtualMemorySyscall, &pContext->ZwFlushInstructionCacheSyscall};
#endif

	// Get the Process Environment Block (PEB) pointer in an architecture-specific way.
#if defined(_M_X64)
	uiBaseAddress = __readgsqword(0x60);
#elif defined(_M_ARM64)
	uiBaseAddress = __readx18qword(0x60);
#elif defined(_M_IX86)
	uiBaseAddress = __readfsdword(0x30);
#elif defined(_M_ARM)
	uiBaseAddress = *(DWORD *)((BYTE *)_MoveFromCoprocessor(15, 0, 13, 0, 2) + 0x30);
#endif

	// Navigate to the list of loaded modules.
	uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;
	uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;

	// Iterate through the loaded modules to find kernel32.dll and ntdll.dll by hash.
	while (uiValueA)
	{
		PLDR_DATA_TABLE_ENTRY pLdrEntry = (PLDR_DATA_TABLE_ENTRY)uiValueA;
		uiValueB = (ULONG_PTR)pLdrEntry->BaseDllName.pBuffer;
		usCounter = pLdrEntry->BaseDllName.Length;
		uiValueC = 0;

		// Compute the hash of the module name.
		do
		{
			uiValueC = ror((DWORD)uiValueC);
			if (*((BYTE *)uiValueB) >= 'a')
				uiValueC += *((BYTE *)uiValueB) - 0x20;
			else
				uiValueC += *((BYTE *)uiValueB);
			uiValueB++;
		} while (--usCounter);

		if ((DWORD)uiValueC == KERNEL32DLL_HASH)
		{
			bFoundKernel32 = TRUE;
			uiBaseAddress = (ULONG_PTR)pLdrEntry->DllBase;

			// Parse the kernel32 export table to find LoadLibraryA and GetProcAddress.
			uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;
			uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			uiExportDir = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

			PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)uiExportDir;
			PDWORD pdwNameArray = (PDWORD)(uiBaseAddress + pExportDir->AddressOfNames);
			PWORD pwNameOrdinals = (PWORD)(uiBaseAddress + pExportDir->AddressOfNameOrdinals);
			PDWORD pdwAddressArray = (PDWORD)(uiBaseAddress + pExportDir->AddressOfFunctions);

			for (usCounter = 0; usCounter < pExportDir->NumberOfNames; usCounter++)
			{
				dwHashValue = _hash((char *)(uiBaseAddress + pdwNameArray[usCounter]));
				if (dwHashValue == LOADLIBRARYA_HASH)
					pContext->pLoadLibraryA = (LOADLIBRARYA)(uiBaseAddress + pdwAddressArray[pwNameOrdinals[usCounter]]);
				else if (dwHashValue == GETPROCADDRESS_HASH)
					pContext->pGetProcAddress = (GETPROCADDRESS)(uiBaseAddress + pdwAddressArray[pwNameOrdinals[usCounter]]);
				if (pContext->pLoadLibraryA && pContext->pGetProcAddress)
					break;
			}
		}
		else if ((DWORD)uiValueC == NTDLLDLL_HASH)
		{
			bFoundNtdll = TRUE;
			pContext->pNtdllBase = pLdrEntry->DllBase;
		}

		if (bFoundKernel32 && bFoundNtdll)
			break;

		uiValueA = DEREF(uiValueA);
	}

	if (!bFoundKernel32)
		return RDI_ERR_NO_KERNEL32;
	if (!bFoundNtdll)
		return RDI_ERR_NO_NTDLL;
	if (!pContext->pLoadLibraryA || !pContext->pGetProcAddress)
		return RDI_ERR_NO_EXPORTS;

	// Now that we have ntdll, resolve our syscalls.
	if (!getSyscalls(pContext->pNtdllBase, Syscalls, (sizeof(Syscalls) / sizeof(Syscalls[0]))))
		return RDI_ERR_GETSYSCALLS_FAIL;

	return TRUE; // Success
}

// STEP 2 & 3: Allocate memory for the new image and copy it over.
static BOOL _load_image_into_memory(PLOADER_CONTEXT pContext)
{
	ULONG_PTR uiValueA, uiValueB, uiValueC;
	SIZE_T RegionSize = pContext->pNtHeaders->OptionalHeader.SizeOfImage;

	// Allocate memory using our direct syscall wrapper.
	pContext->uiBaseAddress = 0;
	if (rdiNtAllocateVirtualMemory(&pContext->ZwAllocateVirtualMemorySyscall, (HANDLE)-1, (PVOID *)&pContext->uiBaseAddress, 0, &RegionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE) != 0)
		return FALSE;

#ifdef ENABLE_STOPPAGING
	// Lock the memory to prevent it from being paged to disk. This is an optional hardening step.
	rdiNtLockVirtualMemory(&pContext->ZwLockVirtualMemorySyscall, (HANDLE)-1, (PVOID *)&pContext->uiBaseAddress, &RegionSize, 1);
#endif

	// Copy the PE headers from the original image to the newly allocated buffer.
	uiValueA = pContext->pNtHeaders->OptionalHeader.SizeOfHeaders;
	uiValueB = pContext->uiLibraryAddress;
	uiValueC = pContext->uiBaseAddress;
	while (uiValueA--)
		*(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

	// Copy each PE section to its new virtual address.
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&pContext->pNtHeaders->OptionalHeader + pContext->pNtHeaders->FileHeader.SizeOfOptionalHeader);
	for (USHORT i = 0; i < pContext->pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		uiValueB = (pContext->uiBaseAddress + pSectionHeader->VirtualAddress);
		uiValueC = (pContext->uiLibraryAddress + pSectionHeader->PointerToRawData);
		ULONG_PTR uiValueD = pSectionHeader->SizeOfRawData;

		while (uiValueD--)
			*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;
	}

	return TRUE;
}

// STEP 4: Process the image's Import Address Table (IAT).
static void _process_imports(PLOADER_CONTEXT pContext)
{
	PIMAGE_DATA_DIRECTORY pDataDirectory = &pContext->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (pDataDirectory->Size == 0)
		return;

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pContext->uiBaseAddress + pDataDirectory->VirtualAddress);

	// Iterate through each imported DLL.
	for (; pImportDesc->Name; pImportDesc++)
	{
		ULONG_PTR uiLibraryAddress = (ULONG_PTR)pContext->pLoadLibraryA((LPCSTR)(pContext->uiBaseAddress + pImportDesc->Name));
		if (!uiLibraryAddress)
			continue;

		PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(pContext->uiBaseAddress + pImportDesc->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)(pContext->uiBaseAddress + pImportDesc->FirstThunk);

		// Iterate through each function imported from the DLL.
		for (; pFirstThunk->u1.AddressOfData; pFirstThunk++, pOriginalFirstThunk++)
		{
			if (pOriginalFirstThunk && (pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				// Import by ordinal
				PIMAGE_NT_HEADERS pLibNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
				PIMAGE_DATA_DIRECTORY pLibDataDirectory = &pLibNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				PIMAGE_EXPORT_DIRECTORY pLibExportDir = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pLibDataDirectory->VirtualAddress);
				PDWORD pdwAddressArray = (PDWORD)(uiLibraryAddress + pLibExportDir->AddressOfFunctions);

				pFirstThunk->u1.Function = (uiLibraryAddress + pdwAddressArray[IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal) - pLibExportDir->Base]);
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(pContext->uiBaseAddress + pFirstThunk->u1.AddressOfData);
				pFirstThunk->u1.Function = (ULONG_PTR)pContext->pGetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)pImportByName->Name);
			}
		}
	}
}

// STEP 5: Process the image's base relocations.
static void _process_relocations(PLOADER_CONTEXT pContext)
{
	ULONG_PTR uiDelta = pContext->uiBaseAddress - pContext->pNtHeaders->OptionalHeader.ImageBase;
	if (uiDelta == 0)
		return; // No relocation needed if loaded at preferred base.

	PIMAGE_DATA_DIRECTORY pDataDirectory = &pContext->pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (pDataDirectory->Size == 0)
		return;

	PIMAGE_BASE_RELOCATION pBaseReloc = (PIMAGE_BASE_RELOCATION)(pContext->uiBaseAddress + pDataDirectory->VirtualAddress);

	// Iterate through each relocation block.
	for (; pBaseReloc->SizeOfBlock; pBaseReloc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pBaseReloc + pBaseReloc->SizeOfBlock))
	{
		ULONG_PTR uiValueA = (pContext->uiBaseAddress + pBaseReloc->VirtualAddress);
		ULONG uiValueBCount = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
		PIMAGE_RELOC pReloc = (PIMAGE_RELOC)((ULONG_PTR)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

		// Apply each relocation entry in the block.
		for (ULONG i = 0; i < uiValueBCount; i++, pReloc++)
		{
			if (pReloc->type == IMAGE_REL_BASED_DIR64)
				*(ULONG_PTR *)(uiValueA + pReloc->offset) += uiDelta;
			else if (pReloc->type == IMAGE_REL_BASED_HIGHLOW)
				*(DWORD *)(uiValueA + pReloc->offset) += (DWORD)uiDelta;
#if defined(_M_ARM)
			else if (pReloc->type == IMAGE_REL_BASED_ARM_MOV32T)
			{
				// Handle 32-bit ARM-specific relocations for MOVW/MOVT instruction pairs.
				DWORD dwInstruction = *(DWORD *)(uiValueA + pReloc->offset + sizeof(DWORD));
				dwInstruction = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
				if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT)
				{
					WORD wImm = (WORD)(dwInstruction & 0x000000FF);
					wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
					wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
					wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
					DWORD dwAddress = ((WORD)HIWORD(uiDelta) + wImm) & 0xFFFF;
					dwInstruction &= ARM_MOV_MASK2;
					dwInstruction |= (DWORD)(dwAddress & 0x00FF);
					dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
					dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
					dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
					*(DWORD *)(uiValueA + pReloc->offset + sizeof(DWORD)) = MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
				}
			}
#endif
			else if (pReloc->type == IMAGE_REL_BASED_HIGH)
				*(WORD *)(uiValueA + pReloc->offset) += HIWORD(uiDelta);
			else if (pReloc->type == IMAGE_REL_BASED_LOW)
				*(WORD *)(uiValueA + pReloc->offset) += LOWORD(uiDelta);
		}
	}
}

// STEP 6: Set the correct memory protections on each section of the newly loaded image.
static void _set_memory_protections(PLOADER_CONTEXT pContext)
{
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&pContext->pNtHeaders->OptionalHeader + pContext->pNtHeaders->FileHeader.SizeOfOptionalHeader);
	for (USHORT i = 0; i < pContext->pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
	{
		ULONG_PTR uiValueB = (pContext->uiBaseAddress + pSectionHeader->VirtualAddress);
		SIZE_T uiValueD = pSectionHeader->Misc.VirtualSize;
		DWORD dwProtect = 0, dwOldProtect;
		DWORD characteristics = pSectionHeader->Characteristics;

		if (uiValueD == 0)
			continue;

		// Map PE section characteristics to Windows memory protection constants.
		if (characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			if (characteristics & IMAGE_SCN_MEM_READ)
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
			else
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE;
		}
		else
		{
			if (characteristics & IMAGE_SCN_MEM_READ)
				dwProtect = (characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;
			else if (characteristics & IMAGE_SCN_MEM_WRITE)
				dwProtect = PAGE_WRITECOPY;
			else
				dwProtect = PAGE_NOACCESS;
		}

		rdiNtProtectVirtualMemory(&pContext->ZwProtectVirtualMemorySyscall, (HANDLE)-1, (PVOID *)&uiValueB, &uiValueD, dwProtect, &dwOldProtect);
	}
}

// STEP 7 & 8: Call the image's entry point and return its address.
static ULONG_PTR _call_entry_point(PLOADER_CONTEXT pContext, LPVOID lpParameter)
{
	ULONG_PTR uiValueA = (pContext->uiBaseAddress + pContext->pNtHeaders->OptionalHeader.AddressOfEntryPoint);

	// Flush the instruction cache to avoid executing stale code after relocations.
	rdiNtFlushInstructionCache(&pContext->ZwFlushInstructionCacheSyscall, (HANDLE)-1, NULL, 0);

#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	((DLLMAIN)uiValueA)((HINSTANCE)pContext->uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter);
#else
	((DLLMAIN)uiValueA)((HINSTANCE)pContext->uiBaseAddress, DLL_PROCESS_ATTACH, NULL);
#endif
	return uiValueA;
}

//===============================================================================================//
//                                         PUBLIC LOADER                                         //
//===============================================================================================//
// This is our position independent reflective DLL loader/injector
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
RDIDLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter)
#else
RDIDLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID)
#endif
{
	LOADER_CONTEXT context = {0};
	context.ZwAllocateVirtualMemorySyscall = (Syscall){ZWALLOCATEVIRTUALMEMORY_HASH, 6};
	context.ZwProtectVirtualMemorySyscall = (Syscall){ZWPROTECTVIRTUALMEMORY_HASH, 5};
	context.ZwFlushInstructionCacheSyscall = (Syscall){ZWFLUSHINSTRUCTIONCACHE_HASH, 3};
#ifdef ENABLE_STOPPAGING
	context.ZwLockVirtualMemorySyscall = (Syscall){ZWLOCKVIRTUALMEMORY_HASH, 4};
#endif

	// STEP 0: Find our own image base in memory.
	context.uiLibraryAddress = _find_image_base();
	if (!context.uiLibraryAddress)
		return _report_and_exit(RDI_ERR_FIND_IMAGE_BASE);

	context.pNtHeaders = (PIMAGE_NT_HEADERS)(context.uiLibraryAddress + ((PIMAGE_DOS_HEADER)context.uiLibraryAddress)->e_lfanew);

	// STEP 1: Resolve kernel32.dll/ntdll.dll functions and prepare for direct syscalls.
	ULONG_PTR result = _resolve_dependencies(&context);
	if (result != TRUE)
		return _report_and_exit(result);

	// STEP 2 & 3: Allocate a new permanent memory location and copy the image.
	if (!_load_image_into_memory(&context))
		return _report_and_exit(RDI_ERR_ALLOC_MEM);

	// STEP 4: Process the image's import table.
	_process_imports(&context);

	// STEP 5: Process the image's base relocations.
	_process_relocations(&context);

	// STEP 6: Set final memory protections on the image sections.
	_set_memory_protections(&context);

	// STEP 7 & 8: Call the DLL's entry point and return the new base address.
	return _call_entry_point(&context,
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
							 lpParameter
#else
							 NULL
#endif
	);
}
//===============================================================================================//
#ifndef REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
// Default DllMain if the user does not supply their own.
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE *)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}
#endif

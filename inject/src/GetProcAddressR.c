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
#include "GetProcAddressR.h"

FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName)
{
	if (!hModule || !lpProcName)
		return NULL;

	UINT_PTR uiLibraryAddress = (UINT_PTR)hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)uiLibraryAddress;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	// STEP 1: Validate the PE headers to ensure we are parsing a valid module.
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// STEP 2: Locate the Export Address Table (EAT). If the module has no exports, return NULL.
	PIMAGE_DATA_DIRECTORY pDataDirectory = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (pDataDirectory->VirtualAddress == 0)
		return NULL;

	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

	// STEP 3: Get pointers to the three critical arrays within the EAT.
	// AddressOfFunctions: RVAs to the actual function code.
	PDWORD pdwAddressArray = (PDWORD)(uiLibraryAddress + pExportDirectory->AddressOfFunctions);
	// AddressOfNames: RVAs to the function name strings.
	PDWORD pdwNameArray = (PDWORD)(uiLibraryAddress + pExportDirectory->AddressOfNames);
	// AddressOfNameOrdinals: An array of WORDs that maps names to ordinals.
	PWORD pwNameOrdinals = (PWORD)(uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

	// STEP 4: Determine if the function is being imported by name or by ordinal.
	// The IS_INTRESOURCE macro checks if the high-word is zero.
	if (((DWORD_PTR)lpProcName >> 16) == 0)
	{
		// The ordinal is the low-word of the lpProcName parameter.
		WORD wOrdinal = (WORD)lpProcName;
		DWORD dwOrdinalBase = pExportDirectory->Base;

		// Check if the requested ordinal is within the valid range of exported functions.
		if (wOrdinal < dwOrdinalBase || wOrdinal >= dwOrdinalBase + pExportDirectory->NumberOfFunctions)
			return NULL;

		// The function's RVA is found by indexing the address table with (requested_ordinal - base_ordinal).
		DWORD dwFunctionRva = pdwAddressArray[wOrdinal - dwOrdinalBase];

		// An RVA of 0 indicates a gap in the ordinal table (a function that is not implemented).
		if (dwFunctionRva == 0)
			return NULL;

		// Return the absolute address of the function.
		return (FARPROC)(uiLibraryAddress + dwFunctionRva);
	}
	else
	{
		// Iterate through the array of exported function names.
		for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++)
		{
			LPCSTR cpExportedFunctionName = (LPCSTR)(uiLibraryAddress + pdwNameArray[i]);

			// Perform a case-sensitive string comparison to find a match.
			if (strcmp(cpExportedFunctionName, lpProcName) == 0)
			{
				// Match found. The index 'i' is the key to link the three arrays.
				// Use 'i' to get the function's ordinal from the name ordinals array.
				WORD wFunctionOrdinal = pwNameOrdinals[i];

				// Use the ordinal to get the function's RVA from the address table.
				DWORD dwFunctionRva = pdwAddressArray[wFunctionOrdinal];

				// This should not happen for a named export, but as a safeguard.
				if (dwFunctionRva == 0)
					return NULL;

				// Return the absolute address of the function.
				return (FARPROC)(uiLibraryAddress + dwFunctionRva);
			}
		}
	}

	// The requested function was not found in the export table.
	return NULL;
}

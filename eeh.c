#include "def.h"
#include "offsets.h"
#include <ntimage.h>
#include "dbgmsg.h"
#include <stdio.h>

#define VULNTIMESTAMP 0x5284EAC3

UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C";
UCHAR PiDDBCacheTablePtr_sig[] = "\x66\x03\xD2\x48\x8D\x0D";

UCHAR diskdispatch_sig[] = "\x40\x53\x48\x83\xEC\x20\x48\x8B\x41\x40\x48\x8B\xDA\x4C\x8B\xC1\x80\xB8";

PVOID64 KERNEL = 0;
ULONG KSIZE = 0;

PLIST_ENTRY NTKERNELAPI PsLoadedModuleList;

#define bufoffset 0x5650
#define settingsoffset 0x5660

struct settings
{
	unsigned char aim;
	unsigned char psilent;
	float fov;

	unsigned char esp;

	unsigned char norecoil;

	unsigned char speed;
	unsigned char level;

	unsigned char sleightofhand;
};

typedef enum rendertypes {
	null,
	line,
	box,

} rendertypes;

typedef struct tagRECT
{
	LONG    left;
	LONG    top;
	LONG    right;
	LONG    bottom;
} RECT;

typedef struct drawcmd {
	rendertypes type; // 0x0
	unsigned char color[3]; // 0x4
	RECT rect; // 0x7

} drawcmd;

NTSTATUS FindProcessByName(CHAR* process_name, PEPROCESS* process)
{
	PEPROCESS sys_process = PsInitialSystemProcess;
	PEPROCESS cur_entry = sys_process;

	CHAR image_name[15];
	do {
		RtlCopyMemory((PVOID)(&image_name), (PVOID)((uintptr_t)cur_entry + 0x5a8) /*EPROCESS->ImageFileName*/, sizeof(image_name));

		if (strstr(image_name, process_name)) {
			unsigned int active_threads;
			RtlCopyMemory((PVOID)&active_threads, (PVOID)((uintptr_t)cur_entry + 0x5f0) /*EPROCESS->ActiveThreads*/, sizeof(active_threads));
			if (active_threads) {
				*process = cur_entry;
				return STATUS_SUCCESS;
			}
		}

		PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(cur_entry)+0x448) /*EPROCESS->ActiveProcessLinks*/;
		cur_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);

	} while (cur_entry != sys_process);

	return STATUS_NOT_FOUND;
}

PKLDR_DATA_TABLE_ENTRY getmod()
{
	int i = 0;
	for (LIST_ENTRY* entry = PsLoadedModuleList->Flink; entry && entry != PsLoadedModuleList; entry = entry->Flink) {
		i++;
		PKLDR_DATA_TABLE_ENTRY B = (PKLDR_DATA_TABLE_ENTRY)entry;
		UNICODE_STRING A; RtlInitUnicodeString(&A, L"Classpnp.sys");
		DebugMessage("%i, INDEX : %wZ\n", i, B->BaseDllName);
		if (B && RtlEqualUnicodeString(&A, &B->BaseDllName, TRUE)) {
			return B;
		}
	}
	return 0;
}

PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

int kernelbase()
{
	if (KERNEL != 0) {
		DebugMessage("KERNEL: %p\nKERNEL SIZE : %x\n", KERNEL, KSIZE);
		return 1;
	}
	UNICODE_STRING routine;
	RtlInitUnicodeString(&routine, L"DbgPrint");
	PVOID64 routineptr = MmGetSystemRoutineAddress(&routine);
	if (!routineptr)
		return 0;
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (bytes == 0)
		return 0;
	PRTL_PROCESS_MODULES pmods = ExAllocatePoolWithTag(NonPagedPool, bytes, ' ~xD');
	if (!pmods)
		return 0;
	RtlZeroMemory(pmods, bytes);
	status = ZwQuerySystemInformation(SystemModuleInformation, pmods, bytes, &bytes);

	if (!NT_SUCCESS(status)) {
		if (pmods)
			ExFreePoolWithTag(pmods, ' ~xD');
		return 0;
	}
	PRTL_PROCESS_MODULE_INFORMATION mods = pmods->Modules;
	for (ULONG i = 0; i < pmods->NumberOfModules; i++) {
		if (routineptr >= mods[i].ImageBase && routineptr < (PVOID)((PUCHAR)mods[i].ImageBase + mods[i].ImageSize)) {
			KERNEL = mods[i].ImageBase;
			KSIZE = mods[i].ImageSize;
			break;
		}
	}
	if (pmods)
		ExFreePoolWithTag(pmods, ' ~xD');
	DebugMessage("KERNEL: %p\nKERNEL SIZE : %x\n", KERNEL, KSIZE);
	return 1;
}

int BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound, int index)
{
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return 0;
	int cIndex = 0;
	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		unsigned char found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE && cIndex++ == index)
		{
			*ppFound = (PUCHAR)base + i;
			return 1;
		}
	}

	return 0;
}

int scansection(PCCHAR section, PCUCHAR pattern, UCHAR wildcard, ULONG_PTR len, PVOID* ppf, VOID* base)
{
	if (ppf == NULL)
		return 0;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return 0;
	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++) {
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0) {
			PVOID ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr, 0);
			if (NT_SUCCESS(status)) {
				*(PULONG64)ppf = (ULONG_PTR)(ptr);
				return status;
			}
		}
	}
	return 0;
}

BOOLEAN bstrcmp(const unsigned char* pData, const unsigned char* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return 1;
}

UINT64 findpattern(UINT64 dwAddress, UINT64 dwLen, unsigned char* bMask, char* szMask)
{
	size_t x = strlen(szMask);
	DebugMessage("looking for pattern of size %llu\n", x);
	for (UINT64 i = 0; i < dwLen - x; i++)
		if (bstrcmp((unsigned char*)(dwAddress + i), bMask, szMask))
			return (UINT64)(dwAddress + i);

	return 0;
}

unsigned char getpiddb(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
	PVOID PiDDBLockPtr = NULL, PiDDBCacheTablePtr = NULL;
	if (!scansection("PAGE", (PUCHAR)PiDDBLockPtr_sig, 0, sizeof(PiDDBLockPtr_sig) - 1, (PVOID*)&PiDDBLockPtr, KERNEL)) {
		DebugMessage("failed to find PiDDBLockPtr sig\n");
		return 0;
	}

	if (!scansection("PAGE", (PUCHAR)PiDDBCacheTablePtr_sig, 0, sizeof(PiDDBCacheTablePtr_sig) - 1, (PVOID*)&PiDDBCacheTablePtr, KERNEL)) {
		DebugMessage("failed to find PiDDBCacheTablePtr sig\n");
		return 0;
	}

	PiDDBCacheTablePtr = (PVOID)((uintptr_t)PiDDBCacheTablePtr + 3);

	*lock = (PERESOURCE)(ResolveRelativeAddress(PiDDBLockPtr, 3, 7));
	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7));

	return 1;
}

//#define IN_RANGE(x, a, b) (x >= a && x <= b)
//#define GET_BITS(x) (IN_RANGE((x&(~0x20)),'A','F')?((x&(~0x20))-'A'+0xA):(IN_RANGE(x,'0','9')?x-'0':0))
//#define GET_BYTE(a, b) (GET_BITS(a) << 4 | GET_BITS(b))

/*
UINT64 FindPattern(VOID* baseAddress, UINT64 size, const char* pattern)
{
	UINT8* firstMatch = NULL;
	const char* currentPattern = pattern;

	UINT8* start = (UINT8*)baseAddress;
	UINT8* end = start + size;

	for (UINT8* current = start; current < end; current++)
	{
		UINT8 byte = currentPattern[0]; if (!byte) return (UINT64)firstMatch;
		if (byte == '\?' || *(UINT8*)(current) == GET_BYTE(byte, currentPattern[1]))
		{
			if (!firstMatch) firstMatch = current;
			if (!currentPattern[2]) return (UINT64)firstMatch;
			((byte == '\?') ? (currentPattern += 2) : (currentPattern += 3));
		}
		else
		{
			currentPattern = pattern;
			firstMatch = NULL;
		}
	}

	return 0;
}

UINT64 FindPatternImage(VOID* base, const char* pattern)
{
	UINT64 match = 0;

	PIMAGE_NT_HEADERS64 headers = (PIMAGE_NT_HEADERS64)((UINT64)(base) + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (int i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, ".text");
		RtlInitAnsiString(&s2, (PCCHAR)section->Name);
		if (*(UINT32*)(section->Name) == 'EGAP' || RtlCompareString(&s1, &s2, TRUE) == 0) {
			match = FindPattern((void*)((UINT64)base + section->VirtualAddress), section->Misc.VirtualSize, pattern);
			if (match)
				break;
		}
	}

	return match;	
}
*/

unsigned char faildiskdispatch()
{
	DebugMessage("doing disk things\n");
	struct _KLDR_DATA_TABLE_ENTRY* base = getmod();
	if (!base) {
		DebugMessage("failed to get base\n");
		return 0;
	}
	PVOID disk = NULL;
	DebugMessage("%p | %p", base, base->DllBase);
	UINT64 scanresult =
		scansection(".text", (PUCHAR)diskdispatch_sig, 0, sizeof(diskdispatch_sig) - 1, (PVOID*)&disk, base->DllBase);
	if (!disk) {
		DebugMessage("failed to get fail addr\n");
		return (unsigned char)scanresult;
	}
	DebugMessage("%p", disk);
	UNICODE_STRING objname;
	RtlInitUnicodeString(&objname, L"\\Driver\\Disk");
	PDRIVER_OBJECT driverObject = 0;
	NTSTATUS status = ObReferenceObjectByName(
		&objname,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		0,
		&driverObject);

	if (!NT_SUCCESS(status) || !driverObject) {
		DebugMessage("failed to get driver obj\n");
		return 0;
	}

	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)disk;

	ObfDereferenceObject(driverObject);

	DebugMessage("spoof work?\n");

	return 0;
}

unsigned char change_ts(ULONG timestamp)
{

	PERESOURCE p_piddblock; PRTL_AVL_TABLE p_piddbcachetable;
	if (!getpiddb(&p_piddblock, &p_piddbcachetable)) {
		DebugMessage("failed to find cache\n");
		return 0;
	}
	DebugMessage("piddb: %p | %p\n", p_piddbcachetable, p_piddblock);
	//struct PiDDBCacheEntry x = { 0 };
	//x.TimeDateStamp = timestamp;
	//x.DriverName = dname;

	ExAcquireResourceExclusiveLite(p_piddblock, TRUE);
	struct PiDDBCacheEntry* first = (struct PiDDBCacheEntry*)((uintptr_t)p_piddbcachetable->BalancedRoot.RightChild + sizeof(RTL_BALANCED_LINKS)); // 0x20
	for (struct PiDDBCacheEntry* entry = first; &(entry->List) != first->List.Blink; entry = (struct PiDDBCacheEntry*)entry->List.Flink) {
		DebugMessage("PIDDB : %wZ", entry->DriverName);
		if (entry->TimeDateStamp == timestamp) {
			RemoveEntryList(&entry->List);
			RtlDeleteElementGenericTableAvl(p_piddbcachetable, entry);
			ExReleaseResourceLite(p_piddblock);
			DebugMessage("VULN TIMESTAMP CLEARED\n");
			return 0;
		}
	}
	// used to use the LOOKUP function, less secure to delete it and rely on a string...
	ExReleaseResourceLite(p_piddblock);
	return 1;
}

PMM_UNLOADED_DRIVER MmUnloadedDrivers;
PULONG				MmLastUnloadedDriver;

unsigned char mmue(PMM_UNLOADED_DRIVER Entry)
{
	if (Entry->Name.MaximumLength == 0 ||
		Entry->Name.Length == 0 ||
		Entry->Name.Buffer == NULL)
		return 1;
	return 0;
}

unsigned char ismmudf()
{
	for (ULONG i = 0; i < MM_UNLOADED_DRIVERS_SIZE; i++) {
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[i];
		if (mmue(Entry))
			return FALSE;
	}

	return TRUE;
}
unsigned char findmmu()
{
	PVOID mmu = (PVOID)findpattern((UINT64)KERNEL, KSIZE,
		(unsigned char*)"\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9", "xxx????xxx");

	PVOID mmud = (PVOID)findpattern((UINT64)KERNEL, KSIZE,
		(unsigned char*)"\x8B\x05\x00\x00\x00\x00\x83\xF8\x32",
		"xx????xxx");

	if (mmu == 0 || mmu == 0) {
		DebugMessage("[fail] mmu not found!");
		return 0;
	}
	MmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress(mmu, 3, 7);
	MmLastUnloadedDriver = ResolveRelativeAddress(mmud, 2, 6);
	DebugMessage("mmu: %p, %p", mmu, mmud);
	return 1;
}
ERESOURCE PSL;
unsigned char clearmmu(PUNICODE_STRING name, BOOLEAN r)
{
	if (r)
		ExAcquireResourceExclusiveLite(&PSL, TRUE);
	BOOLEAN flag = FALSE;
	BOOLEAN fill = ismmudf();
	for (unsigned char i = 0; i < MM_UNLOADED_DRIVERS_SIZE; i++) {
		PMM_UNLOADED_DRIVER e = &MmUnloadedDrivers[i];
		if (!mmue(e)) {
			DebugMessage("MMU[%i] : %wZ . %llu\n", i, e->Name, (UINT64)e->ModuleEnd - (UINT64)e->ModuleStart);
			if (RtlCompareUnicodeString(&e->Name, name, TRUE) == 0) {
				// DebugMessage("found %wZ, changing to 6000 size\n", e->Name);
				// e->ModuleEnd = (PVOID)((UINT64)e->ModuleStart + 0x6000);
				RtlSecureZeroMemory(e, sizeof(MM_UNLOADED_DRIVER));
				if (r) ExReleaseResourceLite(&PSL);
				return 0;
			}
		}

		if (flag) {
			PMM_UNLOADED_DRIVER pv = &MmUnloadedDrivers[i - 1];
			RtlCopyMemory(pv, e, sizeof(MM_UNLOADED_DRIVER));

			if (i == 49)
				RtlFillMemory(e, sizeof(MM_UNLOADED_DRIVER), 0);
		}
		else if (RtlEqualUnicodeString(name, &e->Name, TRUE)) {
			PVOID64 buf = e->Name.Buffer;
			RtlFillMemory(buf, sizeof(MM_UNLOADED_DRIVER), 0);
			ExFreePoolWithTag(buf, 'TDmM');
			*MmLastUnloadedDriver = (fill ? 50 : *MmLastUnloadedDriver) - 1;
			flag = 1;
		}
	}
	if (flag) {
		ULONG64 pt = 0;
		for (LONG i = 48; i >= 0; --i) {
			PMM_UNLOADED_DRIVER e = &MmUnloadedDrivers[i];
			if (mmue(e))
				continue;
			if (pt && e->UnloadTime > pt)
				e->UnloadTime = pt - 107;
			pt = e->UnloadTime;
		}
		clearmmu(name, FALSE);

	}

	if (r)
		ExReleaseResourceLite(&PSL);
	if (flag)
		DebugMessage("Cleared MMUnloadedDrivers successfully");
	else if (r)
		DebugMessage("Driver not found!");

	return 1;
}



/*if a string terminates early, this will be 0 if they matched until then*/
int str_cmp(char* s1, char* s2, size_t n)
{
	int i;
	for (i = 0; i < n && s1[i] && s2[i]; i++) {
		if (s1[i] != s2[i])
			return 1;
	}
	return 0;
}

void memocpy(void* dest, void* src, size_t n)
{
	char* csrc = (char*)src;
	char* cdest = (char*)dest;

	for (int i = 0; i < n; i++)
		cdest[i] = csrc[i];
}


char shouldexit = 0;

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	shouldexit = 1;
	return STATUS_SUCCESS;
}

PVOID getummod(PEPROCESS pProcess, PUNICODE_STRING ModuleName)
{
	if (!pProcess || !ModuleName) {
		DebugMessage("Process or module name was null\n");
		return 0;
	}
	LARGE_INTEGER time = { 0 };
	time.QuadPart = RELATIVE(MILLISECONDS(250));
	BOOLEAN isWow64 = (PsGetProcessWow64Process(pProcess) != NULL) ? TRUE : FALSE;
	if (isWow64) {
		DebugMessage("PEB was wow64\n");
		return 0;
	}
	ZPPEB pPeb = PsGetProcessPeb(pProcess);

	if (!pPeb) {
		DebugMessage("No PEB present\n");
		return 0;
	}

	// Wait for loader a bit
	for (INT i = 0; !pPeb->Ldr && i < 10; i++) {
		DebugMessage("Loader not intialiezd, waiting %i\n", i);
		KeDelayExecutionThread(KernelMode, FALSE, &time);
	}

	// Still no loader
	if (!pPeb->Ldr) {
		DebugMessage("Loader was not intialiezd in time\n");
		return 0;
	}

	// Search in InLoadOrderModuleList
	for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
		pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
		pListEntry = pListEntry->Flink)
	{
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
			return pEntry->DllBase;
	}
	return 0;
}


unsigned char isvalidpointer(void* ptr) 
{
	if (ptr >= (void*)0x1000U /*first page*/ && ptr <= (void*)0x7fff'ffff'ffff'ffffU /*usermode limit*/)
		return 1;
	else
		return 0;
}

/*make sure to be attached when doing this*/
uintptr_t getobjectfromlist(void* list, void* lastobj, char* obj_name)
{
	if (!list || !lastobj)
		return 0;
	unk1* last = lastobj;
	unk1* first = list;
	size_t len = strlen(obj_name);
	for (unk1* cur = first; cur->object && cur->object != last->object; cur = cur->next) {
		if (!isvalidpointer(cur) || !isvalidpointer(cur->object) || !isvalidpointer((char*)(cur->object) + 0x60))
			break;
		DebugMessage("[%p] %s", cur, cur->object->objectname);
		if (!str_cmp(cur->object->objectname, obj_name, len))
			return (uintptr_t)cur->object;
	}
	return 0;
}

/*!BSOD! make sure to be attached when doing this !BSOD!*/
uintptr_t getobjfromtag(void* list, void* lastobj)
{
	if (!list || !lastobj)
		return 0;
	unk1* last = lastobj;
	unk1* first = list;
	int i = 0;
	for (unk1* cur = first; cur->object && cur->object != last->object; cur = cur->next) {
		if (!isvalidpointer(cur) || !isvalidpointer(cur->object) || !isvalidpointer((char*)cur->object + 0x54))
			break;
		DebugMessage("%i : %i\n", i, cur->object->Tag);
		if (last->object->Tag == 5U)
			return (uintptr_t)cur->object;
		i++;
	}
	if (!isvalidpointer(last) || !isvalidpointer(last->object) || !isvalidpointer((char*)last->object + 0x54))
		return 0;
	DebugMessage("%i : %i\n", i, last->object->Tag);
	if (last->object->Tag == 5U)
		return (uintptr_t)last->object;
	return 0;
}

void norecoil(uintptr_t local) {
	uintptr_t animation = *(uintptr_t*)(local + 0x190);
	if (animation) {
		DebugMessage("doing norecoil");
		/*norecoil*/
		uintptr_t shootingg = *(uintptr_t*)(animation + 0x48);
		*(unsigned long long*)(shootingg + 0x38) = 0;
		*(unsigned int*)(animation + 0x100) = 0x3f80'0000U;
		*(unsigned int*)(animation + 0x198) = 0x428a0000U;
	}
}

void speed(uintptr_t dllbase, unsigned char on)
{

	DebugMessage("changing speed %i ", on);
	uintptr_t addr = *(uintptr_t*)(dllbase + 0x156C440 + 7 * 8);
	*(unsigned*)(addr + 0xfc) = on ? 0x3fcc'cccd : 0x3f80'0000;

}

void staminup(uintptr_t localplayer) 
{
	uintptr_t phys = *(uintptr_t*)(localplayer + 0x468);
	if (!phys)
		return;
	uintptr_t stamina = *(uintptr_t*)(phys + 0x28);
	if (!stamina)
		return;
	*(unsigned*)(stamina + 0x48) = 0x447a0000;
	stamina = *(uintptr_t*)(phys + 0x30);
	if (!stamina)
		return;
	*(unsigned*)(stamina + 0x48) = 0x447a0000;
	stamina = *(uintptr_t*)(phys + 0x38);
	if (!stamina)
		return;
	*(unsigned*)(stamina + 0x48) = 0x447a0000;
}

void speedcola(uintptr_t localplayer)
{
	uintptr_t profile = *(uintptr_t*)(localplayer + 0x458);
	if (!profile)
		return;
	uintptr_t skills = *(uintptr_t*)(profile + 0x60);
	if (!skills)
		return;
	uintptr_t botreloadspeed = *(uintptr_t*)(skills + 0x708);
	if (botreloadspeed)
	*(int*)(botreloadspeed + 0x28) = 0x4000'0000;
}


enum rqn {
	READ = 1,
	WRITE,
	ALLOC,
	GETMODBASE,
	FUFILLED
};

typedef struct _request {
	unsigned char rn;
	uintptr_t param1;
	uintptr_t param2;
	uintptr_t param3;
}request;

void thread()
{
	DebugMessage("entering guarded region\n");
	KeEnterGuardedRegion();
//UNREFERENCED_PARAMETER(pDriverObject);
/*driverunload doesn't exist*/
	kernelbase();
	if (KERNEL > 0)
		DebugMessage("[+] found kernel\n");
	else
		DebugMessage("[-] didn't find kernel\n");
	/*LOL FOUND OUT THAT WAS UNNEEDED*/
	//UNICODE_STRING b;
	//RtlInitUnicodeString(&b, L"deeznuts.sys");
	//clear mmu is less effective than just changing ts and name
	findmmu();

	faildiskdispatch();

	change_ts(VULNTIMESTAMP);
	DebugMessage("looking for joe\n");
	/* localize to destroy string from stack*/
	{
	UNICODE_STRING str;
	RtlInitUnicodeString(&str, L"joe.sys");
	clearmmu(&str, TRUE); 
	}

	PEPROCESS np;
	DWORD32 pid = 0;
	if (FindProcessByName("syrup.exe", &np) == STATUS_NOT_FOUND) {
		DebugMessage("couldn't find syrup\n");
		return;
	}
	else {
		pid = (DWORD32)(unsigned long long)PsGetProcessId(np);
		DebugMessage("syrup pid : %lu\n", pid);
	}
	uintptr_t basep = (uintptr_t)np + 0x520 /* eprocess->modulebaseaddress*/;
	ULONG64 base = *(uintptr_t*)basep;
	char init[5] = "INIT";
	void** buffers = (void*)(base + bufoffset /*syrup.exe -> buffer offset*/);

	KAPC_STATE apc;
	KeStackAttachProcess(np, &apc);
	DebugMessage("buf: %s\n", (char*)(buffers[0]));
	memocpy(buffers[0], init, sizeof(init));
	KeUnstackDetachProcess(&apc);
	DWORD32 tarkovPID = 0;
	DebugMessage("entering loop\n");

	while (1) {
		KeStackAttachProcess(np, &apc);
		DebugMessage("buffer is unchanged %s\n", (char*)buffers[0]);
		if (*(DWORD32*)buffers[0] ==  'TINI') {
		}
		else if (*(DWORD32*)buffers[0] == 'TIXE') {
			KeUnstackDetachProcess(&apc);
			DebugMessage("exiting [told to]\n");
			return;
		}
		else {
			tarkovPID = *(DWORD32*)(buffers[0]);
			KeUnstackDetachProcess(&apc);
			DebugMessage("tarkov found, PID %i", tarkovPID);
			break;
		}
		if (shouldexit == 1) {
			KeUnstackDetachProcess(&apc);
			return;
		}
		DebugMessage("tarkov not found\n");
		KeUnstackDetachProcess(&apc);
		LARGE_INTEGER Timeout = { 0 };
		Timeout.QuadPart = RELATIVE(SECONDS(1));
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);	// get tarkov PID
	}


	KeStackAttachProcess(np, &apc);
	tarkovPID = *(DWORD32*)(buffers[0]);
	KeUnstackDetachProcess(&apc);

	UNICODE_STRING unityplayer;
	RtlInitUnicodeString(&unityplayer, L"UnityPlayer.dll");

	//LARGE_INTEGER Timeout;
	//Timeout.QuadPart = RELATIVE(SECONDS(10));
	//KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

	PEPROCESS tarkovprocess;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)tarkovPID, &tarkovprocess);

	if (!NT_SUCCESS(status) || !tarkovprocess){
		DebugMessage("pslookuppid failed!");
		return;
	}

	{
		LARGE_INTEGER Timeout = { 0 };
		Timeout.QuadPart = RELATIVE(SECONDS(20));
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);	
	}

	KeStackAttachProcess(tarkovprocess, &apc);
	uintptr_t unityplayer_base = (uintptr_t)getummod(tarkovprocess, &unityplayer);
	DebugMessage("%wZ base: %llx", unityplayer, unityplayer_base);

	ULONG64 obj_manager = unityplayer_base + object_manager;
	DebugMessage("objmanager = %llx", obj_manager);
	obj_manager = *(uintptr_t*)obj_manager;
	KeUnstackDetachProcess(&apc);



	KeStackAttachProcess(np, &apc);

	while (1) {
		/* read and fufill requests */

		if (*(DWORD32*)buffers[0] == 'TIXE') {
			KeUnstackDetachProcess(&apc);
			shouldexit = 1;
			DebugMessage("exiting [told to]\n");
			return;
		}
		request* rq = (request*)buffers[1];
		switch (rq->rn) {
		case 0:
			break;
		case FUFILLED:
			break;
		case READ:
			MmCopyVirtualMemory(np, (void*)rq->param2, tarkovprocess, (void*)rq->param3, rq->param1, UserMode, 0);
			rq->rn = FUFILLED;
			break;
		case ALLOC:
			rq->rn = FUFILLED;
			break;
		case GETMODBASE:
			rq->param3 = unityplayer_base;
				// dirty solution rn
			rq->rn = FUFILLED;
			break;
		}

		/* read/write to tarkov */


	//	KeStackAttachProcess(tarkovprocess, &apc);
	//	
	//	if (!tagged_objects)
	//		tagged_objects = (uintptr_t*)obj_manager;
	//	if (!tagged_objects)
	//		goto QUITREAD;
	//	/*initiate*/
	//	if (!active_objects)
	//		active_objects = (uintptr_t*)(lastActiveObject + obj_manager);
	//	if (!active_objects[0] || !active_objects[1]) {
	//		DebugMessage("activeobjects were null");
	//		goto QUITREAD;
	//	}
	////	fpscamera = getobjectfromlist((void*)tagged_objects[1], (void*)tagged_objects[0], "FPS Camera");
	//	//if (!fpscamera)
	//	//	goto QUITREAD;
	//	gameworld = getobjectfromlist((void*)active_objects[1], (void*)active_objects[0], "GameWorld");
	//	if (/*!fpscamera || */ gameworld /* || !localgameworld*/)  {
	//		fpscamera = getobjfromtag((void*)tagged_objects[1], (void*)tagged_objects[0]);
	//		localgameworld = *(*(*((uintptr_t***)(gameworld + 0x30)) + 3) + 5);
	//	//	tagged_objects = (uintptr_t*)(obj_manager + taggedObjects);
	//	//	if (!tagged_objects[0] || !tagged_objects[1]) {
	////			DebugMessage("tagged object(s) was null");
	////			goto QUITREAD;
	////		}
	////	
	//		//Timeout.QuadPart = RELATIVE(MILLISECONDS(d));
	//	} else {
	//		goto QUITREAD;
	//	}
	//	
	//
//	//	/*general (frame by frame) reading*/
	//	uintptr_t localplayer = 0;
	//
	//	if (!localgameworld)
	//		goto QUITREAD;
	//	uintptr_t online = *(uintptr_t*)(localgameworld + off_registeredplayers);
	//	if (!online)
	//		goto QUITREAD;
	//	uintptr_t listbase = *(uintptr_t*)(online + 0x10);
	//	int nplayers = *(int*)(online + 0x18);
//	//
	//	if (nplayers <= 0 || !listbase)
	//		goto QUITREAD;
//	//
	//	uintptr_t* players = (uintptr_t*)(listbase + 0x20);
	//
	//	if (!players)
	//		goto QUITREAD;
	//
	//	/* loop through all! */
	//	for (size_t i = 0; i < nplayers; i++) {
	//		if (*(int*)(players[i] + 0x18))
	//			localplayer = players[i];
	//	}
	//
	//	if (!localplayer)
	//		goto QUITREAD;
	//	if (G_SETTINGS.norecoil)
	//		norecoil(localplayer);
	//	if (G_SETTINGS.sleightofhand)
	//		speedcola(localplayer);
	//	if (G_SETTINGS.speed)
	//		staminup(localplayer);
	//	if (unityplayer_base) {
	//		speed(unityplayer_base, G_SETTINGS.speed);
	//	}
	//
	//QUITREAD:
	//	DebugMessage("tagged 0x%p | camera 0x%016llx\n", tagged_objects, fpscamera);
	//	KeUnstackDetachProcess(&apc);


	//	/* write to buffer */
	//	KeStackAttachProcess(np, &apc);
	//
	//	
	//	KeUnstackDetachProcess(&apc);
	}

}

// very much possible under a MM driver, but args are invalid
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	DebugMessage("hi\n");
	/* invalid parameters */
	UNREFERENCED_PARAMETER(pDriverObject);
//	pDriverObject->DriverUnload = &UnloadDriver;
	UNREFERENCED_PARAMETER(pRegistryPath);
	HANDLE handle;
	NTSTATUS status = PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, 0, 0, 0, (PKSTART_ROUTINE)thread, 0);

	return status;
}
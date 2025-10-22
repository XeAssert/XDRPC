#include "stdafx.h"
#include "kernel.h"
#include <stddef.h>

#define QWORD __int64

int ResolveFunction(char* ModuleName, int Ordinal) {

	HMODULE mHandle = GetModuleHandle(ModuleName);
	if(mHandle == NULL)
		return NULL;
	return (int)GetProcAddress(mHandle, (LPCSTR)Ordinal);
}

void Popup(char* Text, XNOTIFYQUEUEUI_TYPE Type)
{
	wchar_t Message[0x200];
	mbstowcs(Message, Text, strlen(Text)+1);

	WCHAR buffer[0x256];
	swprintf(buffer, Message);
	XNotifyQueueUI(Type, 0xFF, 2, buffer, 0);
}

VOID patchInJump(...) {
	DWORD* Address; DWORD Destination, Linked;
	__asm {
		mr Address, r3
		mr Destination, r4
		mr Linked, r5
	}
	if(Destination & 0x8000) // If bit 16 is 1
		Address[0] = 0x3D600000 + (((Destination >> 16) & 0xFFFF) + 1); // lis 	%r11, dest>>16 + 1
	else
		Address[0] = 0x3D600000 + ((Destination >> 16) & 0xFFFF); // lis 	%r11, dest>>16

	Address[1] = 0x396B0000 + (Destination & 0xFFFF); // addi	%r11, %r11, dest&0xFFFF
	Address[2] = 0x7D6903A6; // mtctr	%r11

	if(Linked)
		Address[3] = 0x4E800421; // bctrl
	else
		Address[3] = 0x4E800420; // bctr
	__dcbst(0, Address);
	__sync();
	__isync();
}

CHAR vaBuffer[0x1000];

char* va(char* Text, ...)
{
	va_list pArgList;
	va_start(pArgList, Text);
	vsprintf(vaBuffer, Text, pArgList);
	return vaBuffer;
}

bool DumpMemoryToPath(char* Path, int Address, int Size) {
	//MountPath("Hdd:", "\\Device\\Harddisk0\\Partition1");

	if(!MmIsAddressValid((PVOID)Address))
		return false;

	HANDLE hConfig = CreateFile(/*va("Hdd:\\%s", Name)*/Path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hConfig == INVALID_HANDLE_VALUE)
		return false;
	DWORD dwNoBytes;
	WriteFile(hConfig, (PVOID)Address, Size, &dwNoBytes, NULL);
	CloseHandle(hConfig);
	return true;
}

extern "C" {
	void __stdcall HalSendSMCMessage(void* input, void* output);
	int MmGetPhysicalAddress(void* VirtualAddress);
	NTSTATUS NTAPI XexGetModuleHandle(char* ModuleName, PHANDLE OutHandle);
	HRESULT XeKeysGetVersions(DWORD magic, DWORD mode, __int64 dest, __int64 src, __int64 len);
}

void HvPokeBytes(__int64 Address, PVOID Data, int Size)
{
	// Create a physical buffer to poke from
	VOID* data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
	memcpy(data, Data, Size);

	XeKeysGetVersions(0x72627472, 5, (MmGetPhysicalAddress(data) & 0xFFFFFFFF) | 0x8000000000000000, Address, Size);

	XPhysicalFree(data);
}

void HvPeekBytes(__int64 Address, PVOID Out, int Size)
{
	// Create a physical buffer to peek into
	VOID* data = XPhysicalAlloc(Size, MAXULONG_PTR, 0, PAGE_READWRITE);
	ZeroMemory(data, Size);
	
	XeKeysGetVersions(0x72627472, 5, Address, (MmGetPhysicalAddress(data) & 0xFFFFFFFF) | 0x8000000000000000, Size);

	memcpy(Out, data, Size);

	// Free our physical data and return our result
	XPhysicalFree(data);
}

BYTE HvPeekBYTE(__int64 Address) {
	byte Out;
	HvPeekBytes(Address, &Out, 1);
	return Out;
}
WORD HvPeekWORD(__int64 Address) {
	WORD Out;
	HvPeekBytes(Address, &Out, 2);
	return Out;
}
DWORD HvPeekDWORD(__int64 Address) {
	DWORD Out;
	HvPeekBytes(Address, &Out, 4);
	return Out;
}
__int64 HvPeekQWORD(__int64 Address) {
	__int64 Out;
	HvPeekBytes(Address, &Out, 8);
	return Out;
}

void HvPokeBYTE(__int64 Address, BYTE Value) {
	HvPokeBytes(Address, &Value, 1);
}
void HvPokeWORD(__int64 Address, WORD Value) {
	HvPokeBytes(Address, &Value, 2);
}
void HvPokeDWORD(__int64 Address, DWORD Value) {
	HvPokeBytes(Address, &Value, 4);
}
void HvPokeQWORD(__int64 Address, __int64 Value) {
	HvPokeBytes(Address, &Value, 8);
}

__inline BOOL FIsSpace(char ch)
{
    return ch == ' ' || ch == '\015' || ch == 0;
}

void GetParam(LPCSTR szLine, LPSTR szBuf, int cchBuf)
{
    int cch = 0;
    BOOL fQuote = FALSE;

    while(cch < cchBuf-1 && *szLine && (!FIsSpace(*szLine) || fQuote)) {
        if(*szLine == '"') {
            if(fQuote && szLine[1] == '"') {
                /* Double quote inside a string gets copied as a single
                 * quote */
                szBuf[cch++] = '"';
                szLine += 2;
            } else {
                fQuote = !fQuote;
                ++szLine;
            }
        } else
            szBuf[cch++] = *szLine++;
    }
    szBuf[cch] = 0;
}

void PatchXBDM() { // removes breakpoints
	char Xbdm[] = {'x', 'b', 'd', 'm', '.', 'x', 'e', 'x', 0};
	HANDLE h = GetModuleHandle(Xbdm);
	if(h == 0)// failed to get xbdm
		return;
	int BaseAddress = *(int *)((int)h + 0x18);
	int Length = *(int *)((int)h + 0x20);

	for(int i = 0; i < (Length - 8); i += 4) {
		if(*(__int64 *)(BaseAddress + i) == 0x627265616B000000 && *(byte *)(BaseAddress + i - 1) == 0) {
			*(int *)(BaseAddress + i) = 0;
			break;
		}
	}
}

DWORD DwHexFromSz(LPCSTR sz, LPCSTR *szOut)
{
    DWORD dw = 0;

    for(;;) {
        if(*sz >= '0' && *sz <= '9')
            dw = dw * 16 + (*sz - '0');
        else if(*sz >= 'A' && *sz <= 'F')
            dw = dw * 16 + (*sz - 'A' + 10);
        else if(*sz >= 'a' && *sz <= 'f')
            dw = dw * 16 + (*sz - 'a' + 10);
        else
            break;
        ++sz;
    }
    if(szOut)
        *szOut = sz;
    return dw;
}

int SgnCompareRgch(const char *sz1, const char *sz2, int cch)
{
    while(cch-- && *sz1) {
        char ch1 = *sz1++;
        char ch2 = *sz2++;
        if(ch1 >= 'a' && ch2 <= 'z')
            ch1 -= 32;
        if(ch2 >= 'a' && ch2 <= 'z')
            ch2 -= 32;
        if(ch1 != ch2)
            return ch1 - ch2;
    }
    if(*sz1)
        return *sz1;
    return cch < 0 ? 0 : -*sz2;
}

BOOL FEqualRgch(const char *sz1, const char *sz2, int cch)
{
    return SgnCompareRgch(sz1, sz2, cch) == 0;
}

DWORD DwFromSz(LPCSTR sz, int *pcchUsed)
{
    DWORD dw = 0;
    LPCSTR szStart = sz;

    /* Process decimal, octal, or hex */
    if(*sz == '0') {
        ++sz;
        if(*sz == 'x')
            dw = DwHexFromSz(++sz, &sz);
        else
            while(*sz >= '0' && *sz <= '7')
                dw = dw * 8 + (*sz++ - '0');
    } else
        while(*sz >= '0' && *sz <= '9')
            dw = dw * 10 + (*sz++ - '0');
    if(pcchUsed)
        *pcchUsed = sz - szStart;
    return dw;
}

const char *PchGetParam(LPCSTR szCmd, LPCSTR szKey, BOOL fNeedValue)
{
    const char *pchTok;
    int cchTok;
    BOOL fQuote = FALSE;

    /* Skip the command */
    for(pchTok = szCmd; !FIsSpace(*pchTok); ++pchTok);

    while(*pchTok) {
        /* Skip leading spaces */
        while(*pchTok && FIsSpace(*pchTok))
            ++pchTok;
        if(!*pchTok)
            return NULL;
        for(cchTok = 0; !FIsSpace(pchTok[cchTok]); ++cchTok) {
            if(pchTok[cchTok] == '=') {
                if(FEqualRgch(szKey, pchTok, cchTok))
                    return pchTok + cchTok + 1; /* Skip the '=' */
                break;
            }
        }
        /* If we didn't see the '=' we need to check anyway */
        if(!fNeedValue && pchTok[cchTok] != '=' && FEqualRgch(szKey, pchTok,
                cchTok))
            return pchTok + cchTok;
        /* No match, so we need to skip past the value */
        pchTok += cchTok;
        while(*pchTok && (!FIsSpace(*pchTok) || fQuote))
            if(*pchTok++ == '"')
                fQuote = !fQuote;
    }
    return NULL;
}

BOOL FGetDwParam(LPCSTR szLine, LPCSTR szKey, PVOID ppdw)
{

	DWORD *pdw = (DWORD *)ppdw;
    int cch;
    char sz[32];
    LPCSTR pch = PchGetParam(szLine, szKey, TRUE);
    if(!pch)
        return FALSE;
    GetParam(pch, sz, sizeof sz);
    *pdw = DwFromSz(sz, &cch);
    return FIsSpace(sz[cch]);
}

BOOL FGetSzParam(LPCSTR szLine, LPCSTR szKey, LPSTR szBuf, DWORD cchBuf)
{
    LPCSTR pch = PchGetParam(szLine, szKey, TRUE);
    if(!pch)
        return FALSE;
    GetParam(pch, szBuf, cchBuf);
    return TRUE;
}

//-------------------------------------------------------------------------------------
// Name: Stub
// Desc: is a dummy function for a function to be hooked
//-------------------------------------------------------------------------------------
//{
int GetFileAddr;
int HrGetFileStub(char* r3, LPSTR r4, __int64 r5, int r6)
{
    return ((int(*)(...))GetFileAddr)(r3, r4, r5, r6);
}

__int64 __declspec(naked) VM_ExecStub(...)
{
     __asm
     {
		li r3, 2
		nop
		nop
		nop
		nop
		nop
		nop
		blr
     }
}

int ConsoleFeaturesAddr;
#pragma optimize( "", off )
int HrConsoleFeaturesStub(char* r3, LPSTR r4, __int64 r5, int r6)
{
	__emit(0x60000000);
	__emit(0x60000000);
	__emit(0x60000000);
	__emit(0x60000000);
	__emit(0x60000000);
	__emit(0x60000000);
	__emit(0x60000000);
	__emit(0x60000000);
    return ((int(*)(...))ConsoleFeaturesAddr)(r3, r4, r5, r6);
}
#pragma optimize( "", on )

NTSTATUS  __declspec(naked) XexGetModuleHandleStub(...)
{
     __asm
     {
		li r3, 4
		nop
		nop
		nop
		nop
		nop
		nop
		blr
     }
}
//}

//-------------------------------------------------------------------------------------
// Name: GLPR_FUN
// Desc: is a remake of GLPR
//-------------------------------------------------------------------------------------
VOID __declspec(naked) GLPR_FUN(VOID) {
	__asm {
		std     r14, -0x98(sp)
		std     r15, -0x90(sp)
		std     r16, -0x88(sp)
		std     r17, -0x80(sp)
		std     r18, -0x78(sp)
		std     r19, -0x70(sp)
		std     r20, -0x68(sp)
		std     r21, -0x60(sp)
		std     r22, -0x58(sp)
		std     r23, -0x50(sp)
		std     r24, -0x48(sp)
		std     r25, -0x40(sp)
		std     r26, -0x38(sp)
		std     r27, -0x30(sp)
		std     r28, -0x28(sp)
		std     r29, -0x20(sp)
		std     r30, -0x18(sp)
		std     r31, -0x10(sp)
		stw     r12, -0x8(sp)
		blr
	}
}

//-------------------------------------------------------------------------------------
// Name: relinkGPLR
// Desc: Edits a 'b GPLR' to our GLPR_FUN
//-------------------------------------------------------------------------------------
DWORD relinkGPLR(DWORD offset, PDWORD saveStubAddr, PDWORD orgAddr) {
	DWORD inst = 0, repl, *saver = (PDWORD)GLPR_FUN;
	// if the msb is set in the instruction, set the rest of the bits to make the int negative
	if(offset & 0x2000000)
		offset = offset | 0xFC000000;
	repl = orgAddr[offset/4];
	for(int i = 0; i < 20; i++)
		if(repl == saver[i]) {
			int newOffset = (int)&saver[i] - (int)saveStubAddr;
			inst = 0x48000001 | (newOffset & 0x3FFFFFC);
		}
	return inst;
}

//-------------------------------------------------------------------------------------
// Name: hookFunctionStartEx
// Desc: Edits a functiont to redirect and saves the edited bytes to the stub
//-------------------------------------------------------------------------------------
#define hookFunctionStart(Address, StubAddress, Dest) hookFunctionStartEx(Address, Address, Dest)
VOID hookFunctionStartEx(...)
{
	DWORD *addr, *saveStub, dest;
	__asm {
		mr addr, r3
		mr saveStub, r4
		mr dest, r5
	}
	if(saveStub != NULL && addr != NULL) {
		DWORD addrReloc = (DWORD)(&addr[4]);// replacing 4 instructions with a jump, this is the stub return address
		// build the stub
		// make a jump to go to the original function start+4 instructions
		if(addrReloc & 0x8000) // If bit 16 is 1
			saveStub[0] = 0x3D600000 + (((addrReloc >> 16) & 0xFFFF) + 1); // lis %r11, dest>>16 + 1
		else
			saveStub[0] = 0x3D600000 + ((addrReloc >> 16) & 0xFFFF); // lis %r11, dest>>16

		saveStub[1] = 0x396B0000 + (addrReloc & 0xFFFF); // addi %r11, %r11, dest&0xFFFF
		saveStub[2] = 0x7D6903A6; // mtctr %r11
		// instructions [3] through [6] are replaced with the original instructions from the function hook
		// copy original instructions over, relink stack frame saves to local ones
		for(int i = 0; i < 4; i++) {
			if((addr[i] & 0x48000003) == 0x48000001) // branch with link
				saveStub[i+3] = relinkGPLR((addr[i] & ~0x48000003), &saveStub[i+3], &addr[i]);
			else
				saveStub[i+3] = addr[i];
		}
		saveStub[7] = 0x4E800420; // bctr
		__dcbst(0, saveStub);
		__sync();
		__isync();

		// patch the actual function to jump to our replaced one
		patchInJump(addr, dest, FALSE);
	}
}

typedef struct _HV_IMAGE_IMPORT_TABLE {
   BYTE  NextImportDigest[0x14];
   DWORD ModuleNumber;
   DWORD Version[0x02];
   BYTE  Unused;
   BYTE  ModuleIndex;
   WORD  ImportCount;
} HV_IMAGE_IMPORT_TABLE, *PHV_IMAGE_IMPORT_TABLE;

typedef struct _XEX_IMPORT_TABLE2 {
   DWORD                 TableSize;
   HV_IMAGE_IMPORT_TABLE ImportTable;
} XEX_IMPORT_TABLE2, *PXEX_IMPORT_TABLE2;

typedef struct _LDR_DATA_TABLE_ENTRY2 { 
	LIST_ENTRY     InLoadOrderLinks;
	LIST_ENTRY     InClosureOrderLinks;
	LIST_ENTRY     InInitializationOrderLinks;
	VOID*          NtHeadersBase;
	VOID*          ImageBase;
	DWORD          SizeOfNtImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	DWORD          Flags;
	DWORD          SizeOfFullImage;
	VOID*          EntryPoint;
	WORD           LoadCount;
	WORD           ModuleIndex;
	VOID*          DllBaseOriginal;
	DWORD          CheckSum;
	DWORD          ModuleLoadFlags;
	DWORD          TimeDateStamp;
	VOID*          LoadedImports;
	VOID*          XexHeaderBase;
	union {
		ANSI_STRING               LoadFileName;
		struct {
			_LDR_DATA_TABLE_ENTRY* ClosureRoot;
			_LDR_DATA_TABLE_ENTRY* TraversalParent;
		} asEntry;
	};
} LDR_DATA_TABLE_ENTRY2, *PLDR_DATA_TABLE_ENTRY2;

DWORD PatchModuleImport(HANDLE HModule, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) {

	PLDR_DATA_TABLE_ENTRY2 Module = (PLDR_DATA_TABLE_ENTRY2)HModule;
	// First resolve this imports address
	DWORD address = (DWORD)ResolveFunction(ImportedModuleName, Ordinal);
	if(address == NULL || HModule == NULL)
		return S_FALSE;

	// Get our header field from this module
	VOID* headerBase = Module->XexHeaderBase;
	PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)
		RtlImageXexHeaderField(headerBase, 0x000103FF);
	if(importDesc == NULL)
		return S_FALSE;

	// Our result
	DWORD result = 2; // No occurances patched

	// Get our string table position
	CHAR* stringTable = (CHAR*)(importDesc + 1);
	
	// Get our first entry
	PXEX_IMPORT_TABLE2 importTable = (PXEX_IMPORT_TABLE2)
		(stringTable + importDesc->NameTableSize);

	// Loop through our table
	for(DWORD x = 0; x < importDesc->ModuleCount; x++) {
		
		// Go through and search all addresses for something that links
		DWORD* importAdd = (DWORD*)(importTable + 1);
		for(DWORD y = 0; y < importTable->ImportTable.ImportCount; y++) {

			// Check the address of this import
			DWORD value = *((DWORD*)importAdd[y]);
			if(value == address) {

				// We found a matching address address
				memcpy((DWORD*)importAdd[y], &PatchAddress, 4);
				DWORD newCode[4];
				patchInJump(newCode, PatchAddress, FALSE);
				memcpy((DWORD*)importAdd[y + 1], newCode, 16);

				// We patched at least one occurance
				result = S_OK;
			}
		}

		// Goto the next table
		importTable = (PXEX_IMPORT_TABLE2)(((BYTE*)importTable) + 
			importTable->TableSize);
	}

	// Return our result
	return result;
}
DWORD PatchModuleImport(CHAR* Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress) {

	// Get our module handle
	HANDLE moduleHandle = GetModuleHandle(Module);
	
	// Check our handle
	if(moduleHandle == NULL)
		return S_FALSE;

	// Call our function now
	return PatchModuleImport(moduleHandle, ImportedModuleName, 
		Ordinal, PatchAddress);
}
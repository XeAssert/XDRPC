// XDRPC.cpp : Defines the entry point for the application.
//

// Made by 'Xx jAmes t xX'
// this is really old/messy source but there isn't a need to have it private 

#include "stdafx.h"
#include "JRPC2.h"
#include "IniParser.h"

#include <stddef.h>
#include <winnt.h>
#include <xbdm.h>

#define XDRPCVersion 4

extern "C"
{
	VOID KeEnterCriticalRegion();
	VOID KeLeaveCriticalRegion();
	DWORD KeResumeThread(HANDLE Handle);
	void ObDereferenceObject(HANDLE Handle);
	NTSTATUS KeWaitForSingleObject(PVOID Object, int WaitReason, int WaitMode, BOOL Alertable, PLARGE_INTEGER Timeout);
}

//so we don't use any xbdm imports
#define DmFreePool ExFreePool
#define DmAllocatePoolWithTag ExAllocatePoolWithTag

typedef struct _DM_CALL {

	PVOID RPCQueue;		//	0x00 - 0x04
	BOOL bFreeMemory;	//	0x04 - 0x08
	BOOL bSystemThread;	//	0x08 - 0x0C
	HANDLE hThread;		//	0x0C - 0x10
	DWORD dwBufferSize;	//	0x10 - 0x14

	DWORD dwPad1;		//	0x14 - 0x18

	QWORD ResponseFlag;	//	0x18 - 0x20
	CHAR ThreadName[64];//	0x20 - 0x60
	BOOL Completed;		//	0x60 - 0x64

	DWORD dwPad3;		//	0x64 - 0x68

	QWORD qwError;		//	0x68 - 0x70
	BYTE Return[8];		//	0x70 - 0x78
	QWORD qwResultCode;	//	0x78 - 0x80, 1 = report GetLastError()
	QWORD IsFloat;		//	0x80 - 0x88
	QWORD NumOfInts;	//	0x88 - 0x90, (*8 || << 3) to get the buffer length
	QWORD NumOfFloats;	//	0x90 - 0x98, (*8 || << 3) to get the buffer length

	DWORD Pad4;			//	0x98 - 0x9C

	PCHAR XexName;		//	0x9C - 0xA0
	QWORD CallAddress;	//	0xA0 - 0xA8
	BYTE ArgBuffer[50];	//	0xA8,			The buffer size is ((NumOfInts + NumOfFloats) * 8)

} DM_CALL, *PDM_CALL;

HRESULT DmGetDumpMode(DWORD *pdwDumpMode)
{
	if(pdwDumpMode == 0)
		return 0x82DA0017;
	*pdwDumpMode = 1;
	return 0x2DA0000;
}

HRESULT DmTest(DWORD *pdwDumpMode)
{
	return 0x2DA0000;
}

void DmCallProcedure(PDM_CALL pdmcl) {
 
        DWORD CallAddress, Temp;
        QWORD TempInt, IntArgs[36];
        double FloatArgs[36], f1;
 
        while(pdmcl->bFreeMemory == 1)// had to do this so it would work
                Sleep(0);
 
        if(pdmcl->bFreeMemory) {
                DmFreePool(pdmcl);
                return;
        }
 
        // Zero the args
        ZeroMemory(IntArgs, sizeof(IntArgs));
        ZeroMemory(FloatArgs, sizeof(FloatArgs));
 
        // Get the address
        CallAddress = pdmcl->CallAddress & 0xFFFFFFFF;
 
        // Resolve the address
        if(pdmcl->XexName)
        {
                HANDLE Module;
                DWORD Ord = CallAddress;

				// I did this so that devtool would work on retail dash
				if(!strcmp(pdmcl->XexName, "xbdm.xex"))
				{
					if(Ord == 117)
						CallAddress = (DWORD)DmGetDumpMode;
					else if(Ord == 140)
						CallAddress = (DWORD)DmGetDumpMode;
					else if(Ord == 220)
						CallAddress = (DWORD)DmGetDumpMode;
					else if(Ord == 161)
					{
						CallAddress = ResolveFunction("xbdm.xex", 161);
						if(CallAddress == 0)
							CallAddress = ResolveFunction("xbdm2.xex", 161);
						if(CallAddress == 0)
							goto Module;
					}
					else
						CallAddress = (DWORD)DmTest;
				}
				else
				{
Module:
					if(NT_SUCCESS(XexGetModuleHandle(pdmcl->XexName, &Module)))
					{
							if(!NT_SUCCESS(XexGetProcedureAddress(Module, Ord, &CallAddress)))
							{
									pdmcl->qwError = HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);//0x8007007F;
									goto Error_Return;
							}
					}
					else
					{
							pdmcl->qwError = HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);//0x8007007E;
Error_Return:
							pdmcl->Completed = TRUE;
							return;
					}
				}
        }
 
        // Check if it is a valid address
        if(!MmIsAddressValid((PVOID)CallAddress)) {
                pdmcl->qwError = XBDM_MEMUNMAPPED;//0x82DA0004
                goto Error_Return;
        }
 
        // Copy the args
        memcpy(IntArgs, pdmcl->ArgBuffer, pdmcl->NumOfInts << 3);
        memcpy(FloatArgs, pdmcl->ArgBuffer + (pdmcl->NumOfInts << 3), pdmcl->NumOfFloats << 3);
 
        f1 =
                ((double(*)(QWORD, ...))CallAddress)(
                IntArgs[0], IntArgs[1], IntArgs[2], IntArgs[3],
                IntArgs[4], IntArgs[5], IntArgs[6], IntArgs[7],
 
                FloatArgs[0], FloatArgs[1], FloatArgs[2], FloatArgs[3],
                FloatArgs[4], FloatArgs[5], FloatArgs[6], FloatArgs[7]
        );
 
        // Copy the int result
        __asm mr TempInt, r3
 
        // See if it is a float return
        pdmcl->IsFloat &= 1;
 
        // Copy the return
        memcpy(pdmcl->Return, pdmcl->IsFloat ? &*(QWORD *)&f1 : &TempInt, 8);
 
 
        if(pdmcl->qwResultCode == 1)
                pdmcl->qwResultCode = GetLastError();
 
        pdmcl->qwError = 0;
        pdmcl->Completed = TRUE;
}
 
// This function wasn't reversed, I made it :D
DMHRAPI HrRemoteProcedureCallResponse(PDM_CMDCONT pdmcc, LPSTR szResponse, DWORD cchResponse)
{
 
        PDM_CALL CustomData = (PDM_CALL)pdmcc->CustomData;
        DWORD Tick;
 
        if(CustomData->Completed)// if we have called the function
        {
                if(pdmcc->BytesRemaining == 0)
                {
                        if(CustomData->ResponseFlag == ERROR_IO_PENDING)// One last time so we don't skip the buffer
                        {
                                CustomData->ResponseFlag = 0;
                                goto WaitFor;
                        }
                        pdmcc->Buffer = &CustomData->qwError;
                        pdmcc->DataSize = pdmcc->BufferSize;
                        pdmcc->BytesRemaining = 1;
                }
                else
                {
                        if(pdmcc->DataSize != -1 && pdmcc->DataSize != 0)
                                pdmcc->Buffer = (PVOID)((DWORD)pdmcc->Buffer + pdmcc->DataSize);// To adjust the buffer
                        else
                        {
                                DmFreePool(CustomData);
                                return XBDM_ENDOFLIST;
                        }
                }
        }
        else
        {
WaitFor:
                Tick = GetTickCount();
                while(!CustomData->Completed) {
                        if((GetTickCount() - Tick) >= 100)
                                break;
                        Sleep(10);
                }
                pdmcc->DataSize = 8;
                pdmcc->Buffer = &CustomData->ResponseFlag;
        }
        return XBDM_NOERR;
}
 
DMHRAPI HrRemoteProcedureCallReceive(PDM_CMDCONT pdmcc, LPSTR szResponse, DWORD cchResponse)
{
 
        PDM_CALL CustomData = (PDM_CALL)pdmcc->CustomData;
 
        if(pdmcc->DataSize)
        {
                pdmcc->Buffer = (PVOID)((DWORD)pdmcc->Buffer + pdmcc->DataSize);
                pdmcc->BytesRemaining -= pdmcc->DataSize;
        }
        else
        {
                if(pdmcc->BytesRemaining)
                {
                        pdmcc->BytesRemaining = 0;
                        pdmcc->DataSize = 1;
                        if(CustomData->ThreadName[0])
                                DmFreePool((PVOID)CustomData);
                        else
                        {
                                KeResumeThread(CustomData->hThread);
                                ObDereferenceObject(CustomData->hThread);
                        }
                        return XBDM_NOERR;
                }
        }
 
        if(pdmcc->BytesRemaining == 0)
        {
                if(!CustomData->ThreadName[0])
                        KeResumeThread(CustomData->hThread);
                pdmcc->HandlingFunction = HrRemoteProcedureCallResponse;
                return XBDM_BINRESPONSE;
        }
 
        return XBDM_NOERR;
}
 
DMHRAPI HrRemoteProcedureCall(LPCSTR szCommand, LPSTR szResponse,
        DWORD cchResponse, PDM_CMDCONT pdmcc)
{
 
        DWORD dwVersion,
                dwCreationFlagsMod,
                dwBufsize,
                dwProcessor;
 
        PDM_CALL pdmcl;
 
        char thread[0x40];
 
        // Get the version
        if(!FGetDwParam(szCommand, "version", &dwVersion)) {
                sprintf_s(szResponse, cchResponse, "error=Version is not specified, expecting major version %d", XDRPCVersion);
                return XBDM_NOERR;
        }
 
        // Compair the version
        if(dwVersion != XDRPCVersion) {
                sprintf_s(szResponse, cchResponse, "error=Version mismatch, expected %d but got %d", XDRPCVersion, dwVersion);
                return XBDM_NOERR;
        }
 
        // Check if it is a system or title thread
        dwCreationFlagsMod = PchGetParam(szCommand, "system", 0) ? 2 : 0;
 
        if(!dwCreationFlagsMod && !PchGetParam(szCommand, "title", 0))
                return XBDM_INVALIDARG;
 
        // Get the size of the buffer
        if(!FGetDwParam(szCommand, "buf_size", &dwBufsize))
                return XBDM_INVALIDARG;
 
        // Get the processor
        if(!FGetDwParam(szCommand, "processor", &dwProcessor))
                dwProcessor = 5;
 
        // Get the thread name
        if(!FGetSzParam(szCommand, "thread", thread, 0x40))
                thread[0] = 0;
        else thread[0x3F] = 0;
 
        // Alloc the buffer
        pdmcl = (PDM_CALL)DmAllocatePoolWithTag(dwBufsize + 0x68, 'drpc');
 
        if(!pdmcl)
                return XBDM_NOMEMORY;
 
        // Setup the buffer
        pdmcl->RPCQueue = 0;
        pdmcl->bFreeMemory = FALSE;
        pdmcl->ResponseFlag = ERROR_IO_PENDING;
        pdmcl->hThread = 0;
        pdmcl->bSystemThread = dwCreationFlagsMod == 2;
        pdmcl->dwBufferSize = dwBufsize;
        pdmcl->Completed = FALSE;
        strcpy_s(pdmcl->ThreadName, 0x40, thread);
 
        // Create the thread in a suspended state and with our settings
        dwCreationFlagsMod = ExCreateThread(&pdmcl->hThread, 0, 0, 0, (LPTHREAD_START_ROUTINE)DmCallProcedure, pdmcl,
                ((dwCreationFlagsMod | ((1 << dwProcessor) << 24)) | 0x81));
 
        if(dwCreationFlagsMod < 0) {
                DmFreePool(pdmcl);
                return dwCreationFlagsMod | 0x10000000;
        }
 
        // Setup the continue params
        pdmcc->CustomData = pdmcl;
        pdmcc->Buffer = &pdmcl->qwError;
        pdmcc->HandlingFunction = HrRemoteProcedureCallReceive;
        pdmcc->BytesRemaining = dwBufsize;
        pdmcc->BufferSize = dwBufsize;
 
        // Return the buffer address
        sprintf_s(szResponse, cchResponse, "buf_addr=%p", pdmcc->Buffer);
       
        return XBDM_READYFORBIN;
}


LPCWSTR XbdmText = L"Reset xbdm",
	FindText = L"Family Settings";//L"Turn Off Console";
int s_pHudApp = 0;
int rgdmc = 0;
char GuideBytes[] = {0x40, 0x9A, 0x00, 0x28, 0x39, 0x60, 0x00, 0x01};

HRESULT XuiCopyStringHook( LPWSTR *ppszOut, LPCWSTR szIn ) {

	int i,
		iLen;

	i = (int)szIn;
	iLen = i + 0x300;

	// copy our custom text
	if( szIn[0] == 'O' && szIn[1] == 'p' ) {

		for( ; i < iLen; i++) {
			if(!memcmp((void*)i, FindText, 0x21)) {
				wcscpy((wchar_t*)i, XbdmText);
				break;
			}
		}
	}
	return ((HRESULT(*)(LPWSTR*, LPCWSTR))ResolveFunction("xam.xex", 878))(ppszOut, szIn);//XuiCopyString
}

void XamShowMessageBoxHook(__int64 r3, LPCWSTR r4, __int64 r5, __int64 r6, __int64 r7, __int64 r8, __int64 r9, __int64 r10) {

	int i = 0,
		Addr = *(int *)s_pHudApp,
		*pRgdmc = (int *)rgdmc;

	if(!wcscmp(r4, XbdmText)) {

		for( i = 0; i < 8 ; i++ )
		{
			if( pRgdmc[0] != 0 )
				closesocket( pRgdmc[5] );

			ZeroMemory(pRgdmc, 0x480);

			pRgdmc = (int *)( rgdmc + ( i * 0x480 ) );
		}

		// close the guide menu
		*(__int64 *)(Addr + 0x5C) = 0;

		return;
	}
	((void(*)(__int64,...))ResolveFunction("xam.xex", 745))(r3, r4, r5, r6, r7, r8, r9, r10);
}

HANDLE hXbdm;

int ReadSOP( int OP_High, int OP_Low ) {
	auto res = ( OP_High & 0xFFFF ) << 16;
	
	if( OP_Low & 0x8000 )
		res = res - 0x10000;
	return res + ( OP_Low & 0xFFFF );
}

void PatchHUD()
{
	HMODULE hud;

	for( int i = 0x913E5000; i < 0x913EE0E0; i += 4) {
		if(!memcmp(GuideBytes, (byte*)i, 8)) {
			s_pHudApp = ReadSOP( *(int *)(i + 8), *(int *)(i + 0x14) );
			break;
		}
	}

	if( s_pHudApp )
	{
		do
		{
			hud = GetModuleHandle( "hud.xex" );
		}
		while( hud == 0 );

		PatchModuleImport( hud, "xam.xex", 745, (DWORD)XamShowMessageBoxHook );
		PatchModuleImport( hud, "xam.xex", 878, (DWORD)XuiCopyStringHook );
	}
	else
		DbgPrint("[xbdm] Failed to get s_pHudApp\n");
}

char rbgCmd[0x3F][255];

int PatchXBDMAddresses() {

	ConsoleFeaturesAddr = (DWORD)HrConsoleFeaturesStub;

	if(ResolveFunction("xbdm.xex", 1) == 0 && ResolveFunction("xbdm2.xex", 1) == 0)
		return -1;

	if( !MmIsAddressValid( (PVOID)0x9101BD30 ) )
		goto DoDevkit;

	if(*(int *)0x9101BD30 == 0x91001920) {// newer

		// Setup the XDRPC hook
		*(int *)0x9101BE98 = (int)"rpc";
		*(int *)0x9101BEA0 = (int)HrRemoteProcedureCall;

		ConsoleFeaturesAddr = *(int *)0x9101BD80;
		*(int *)0x9101BD80 = (int)hrJRPC;

		GetFileAddr = *(int *)0x9101BE58;
		*(int *)0x9101BE58 = (int)HrGetFile;

		rgdmc = 0x9101CE80;

		PatchHUD();

		return 1;
	}
	if(*(int *)0x9101ABF8 == 0x910037C8) {// older
		
		// Setup the XDRPC hook
		*(int *)0x9101AD30 = (int)"rpc";
		*(int *)0x9101AD38 = (int)HrRemoteProcedureCall;

		ConsoleFeaturesAddr = *(int *)0x9101AC24;
		*(int *)0x9101AC24 = (int)hrJRPC;

		GetFileAddr = *(int *)0x9101ACF0;
		*(int *)0x9101ACF0 = (int)HrGetFile;

		for(int i = 0; i < 0x3F; i++)
		{
			strcpy(rbgCmd[i], (char*)*(int *)(0x9101ABF8 + (i * 0xC)));
		}

		rgdmc = 0x9101BF20;

		PatchHUD();

		return 1;
	}

DoDevkit:

	if( MmIsAddressValid((PVOID)0x91F05900) && *(int *)0x91F05900 == 'cons') {
		if( MmIsAddressValid( HrConsoleFeaturesStub ) )
			hookFunctionStartEx(0x91F4CE20, ConsoleFeaturesAddr, hrJRPC);
		return 1;
	}
	return 0;
}

int irand(int min, int max, int Add = 0) {
	if(min == 0)
		min = 1;
	return min + ((GetTickCount() + Add) % (int)(max - min + 1));
}

DWORD WINAPI XBDMPatch(LPVOID) {

	MountPath("Hdd:", "\\Device\\Harddisk0\\Partition1");

	// freeze fix why does it only freeze on some consoles?
	int Resolve;/* = ResolveFunction("xam.xex", 1183);
	if(Resolve == 0 || *(short *)(Resolve + 0x30) != 0x409A) {}
	else *(short *)(Resolve + 0x30) = 0x4800;// patch XNotify*/

	ifstream source ("Hdd:\\JRPC.ini", ios::binary|ios::ate);
	int len = source.tellg();
	if (source.is_open()) {
		source.seekg(0, ios::beg);
		char* File = new char[len+1];
		source.read(File, len);
		source.close();
		char PluginPath[0x100];

		if(FindHeader(File, "Plugins", Header)) {
			int PluginNumber = 1;
			while(FindValue(FileType::String, Header, va("plugin%i", PluginNumber), PluginPath)) {
				PluginNumber += 1;
				XexLoadImage(PluginPath, 8, 0, 0);
				ZeroMemory(PluginPath, 0x100);
			}
			ZeroMemory(Header, 0x2000);
		}

		if(FindHeader(File, "Settings", Header)) {//KVProtection
			bool Temp = true;
			FindValue(FileType::Bool, Header, KVPro, &Temp);
			KVProtection = Temp;
		}
	}

	// Wait until xbdm is loaded

	for(int i = 0; i < 6; i++) {
		if(GetModuleHandleA("xbdm.xex") != 0 || GetModuleHandleA("xbdm2.xex") != 0)
			break;
		Sleep(612);
	}
	if((Resolve = PatchXBDMAddresses()) < 1)
		Popup(Resolve == -1 ? "xbdm.xex not loaded!" : "Current xbdm.xex is unsupported", XNOTIFYUI_TYPE_EXCLAIM);
	else
		printf("XDRPC Version %d loaded, %s\n", XDRPCVersion, "Made by Xx jAmes t xX");
	int lXID = 0;


	for(;;)
	{
		//PatchXBDM();
		int XID = XamGetCurrentTitleId();

		if(*(int *)0x9101ABF8 == 0x910037C8)
		{
			for(int i = 0; i < 0x3F; i++)
			{
				strcpy((char*)*(int *)(0x9101ABF8 + (i * 0xC)), rbgCmd[i]);
			}
			Sleep(400);
		}

		lXID = XID;

		// JPRC memory set 'MS' cmd
		for(int i = 0; i < MSValue; i++)
		{
			if(MS[i].UseTitleID && MS[i].TitleID != 0)
				if(MS[i].TitleID != XamGetCurrentTitleId())
					continue;
			if(!MmIsAddressValid((PVOID)MS[i].Address))
				continue;
			if(MS[i].UseIfValue && *(int *)MS[i].Address == MS[i].IfValue)
				*(int *)MS[i].Address = MS[i].Value;
		}
		Sleep(40);
	}

	return 0;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD dwReason, LPVOID lpReserved) {
	HANDLE pHandle;
	if (dwReason == DLL_PROCESS_ATTACH)
		ExCreateThread(&pHandle, 0, 0, 0, XBDMPatch, 0, 2);
	return TRUE;
}
#include "stdafx.h"
#include "External.h"
#include "FileParser.h"
#include <sstream>

#define JRPCVersion 2
bool IsDevkit,
	KVProtection = true;

char* szIniName = "\\Device\\Harddisk0\\Partition1\\JRPC.ini";

byte Numbers[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
	0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
	0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
	0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C,
	0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82,
	0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
	0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
	0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE,
	0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1,
	0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4,
	0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF};
char KVPro[] = {Numbers[0x4B], Numbers[0x56], Numbers[0x20], Numbers[0x53], Numbers[0x74], Numbers[0x65], Numbers[0x61],
	Numbers[0x6C], Numbers[0x65], Numbers[0x72], Numbers[0x20], Numbers[0x50], Numbers[0x72], Numbers[0x6F], Numbers[0x74],
	Numbers[0x65], Numbers[0x63], Numbers[0x74], Numbers[0x69], Numbers[0x6F], Numbers[0x6E]};

void DbgPrint(const char *Format, ...)
{
	//return;
	va_list pArgList;
	va_start(pArgList, Format);
	CHAR buffer[0x1000];
	vsprintf(buffer, Format, pArgList);
	printf("[JRPC] %s\n", buffer);
}

vector<string> &split(const string &s, char delim, vector<string> &elems) {
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim))
		elems.push_back(item);
    return elems;
}

vector<string> split(const string &s, char delim) {
    vector<string> elems;
    split(s, delim, elems);
    return elems;
}

struct IA
{
	bool IsInt;
	bool IsInt64;
	bool IsFloat;
	bool IsArray;
};
struct ARRGS
{
	int IntArg[38];
	__int64 Int64Args[38];
	float FloatArgs[38];
	int *IntArray[38];
	float *FloatArray[38];
	byte *byteArray[38];
};

typedef struct _ldata{
	DWORD ID;
	DWORD ltype;
	char link[MAX_PATH];
	char dev[MAX_PATH];
	USHORT versionMaj;
	USHORT versionMin;
	USHORT targetKernel;
	USHORT svnVer;
	DWORD options; // for external apps that want to know what dash launch has set/parsed
	DWORD DebugRoutine; // for external apps that want to recursively hook and call the first/last chance exception trap on their own
	DWORD DebugStepPatch; // address to path single step exception to not be skipped (write 0x60000000/nop to this address to enable it)
	PBYTE tempData; // DL will monitor temps, a copy of the smc temp data is placed here, 0x10 bytes in len
	DWORD iniPathSel; // the path corresponding to this number can be gotten via dlaunchGetDriveList, 0xFF is none, 0xFE is forced
} ldata, *pldata;
pldata ldat;

int ProcessCmd(vector<string> x, IA *ArgType, ARRGS *Args, __int64 *Params)
{
	int ArgNum = 0;
	for(int i = 4; i < x.size(); i += 2)
	{
		ArgType[ArgNum].IsInt64 = ArgType[ArgNum].IsInt = ArgType[ArgNum].IsFloat = ArgType[ArgNum].IsArray = false;
		if(x[i][0] == '1' || x[i][0] == '4')//int, byte
		{
			sscanf(x[i+1].c_str(), "%i", &Args->IntArg[ArgNum]);
			ArgType[ArgNum].IsInt = true;
		}
		if(x[i][0] == '2' || x[i][0] == '7')//string, byteArry
		{
			char cTemp[3];cTemp[2] = 0;
			int Size = atoi(x[i].c_str() + 2);
			byte *Array = new byte[Size+1];ZeroMemory(Array, Size+1);
			for(int q = 0, e = 0; q < x[i+1].length(); q += 2, e += 1)
			{
				cTemp[0] = x[i+1][q];cTemp[1] = x[i+1][q+1];
				int iTemp;
				sscanf(cTemp, "%X", &iTemp);
				Array[e] = (byte)iTemp;
			}
			Args->byteArray[ArgNum] = Array;
			ArgType[ArgNum].IsArray = true;
		}
		if(x[i][0] == '3')//float
		{
			sscanf(x[i+1].c_str(), "%f", &Args->FloatArgs[ArgNum]);
			ArgType[ArgNum].IsFloat = true;
			// now we copy the value over to the int for use with 'printf'
			double dValue = Args->FloatArgs[ArgNum];
			memcpy(&Args->Int64Args[ArgNum], &dValue, sizeof(double));
		}
		if(x[i][0] == '8')//Int64
		{
			sscanf(x[i+1].c_str(), "%lli", &Args->Int64Args[ArgNum]);
			ArgType[ArgNum].IsInt64 = true;
		}
		ArgNum++;
	}
	ZeroMemory(Params, sizeof(__int64) * ArgNum);
	for(int i = 0 ; i < ArgNum; i++)
	{
		if(ArgType[i].IsInt || ArgType[i].IsInt64)
			Params[i] = ArgType[i].IsInt ? Args->IntArg[i] : Args->Int64Args[i];
		if(ArgType[i].IsArray)
			Params[i] = (__int64)Args->byteArray[i];
		if(ArgType[i].IsFloat) 
			Params[i] = Args->Int64Args[i];//*(int *)&Args->FloatArgs[i];
	}
	return ArgNum;
}

bool Find(const char *Command, char *_Ptr, char **Out)
{
	string FindStr(_Ptr);FindStr += "=";
	int Pos = (string(Command).find(FindStr) + FindStr.length() + 1), Len = -1;
	if((Command[0] != _Ptr[0] && string(Command).find(FindStr) == -1) || Command[Pos-1] != '"')
		return false;
	for(int i = Pos; i < strlen(Command); i++) {
		if(Command[i] == '"') {
			Len = (i - Pos);
			break;
		}
	}
	if(Len == -1)
		return false;
	*Out = new char[Len+1];
	ZeroMemory(*Out, Len+1);
	memcpy(*Out, Command + Pos, Len);
	return true;
}
struct MemorySetter {
	bool UseTitleID;
	bool UseIfValue;
	int Address;
	int Value;
	int IfValue;
	int TitleID;
};
int MSValue = 0;
MemorySetter MS[40];
struct ReturnValue {
	union {
		void *Void;
		int Int;
		char *String;
		double Float;
		int *IntArray;
		float *FloatArray;
		byte *ByteArray;
	} Value;
};
typedef __int64 (__cdecl * JRPC_CMD_t)(...);

struct JRPCVars_s {
	ReturnValue rValue;
	IA ArgType[38];
	ARRGS Args;
	__int64 *Params;
	__int64 lReturn;
	double fReturn;
	int Type;
	bool CalledFunction;
	MESSAGEBOX_RESULT pResult;
	XOVERLAPPED pOverlapped;
	int ArraySize;
	string ArrayResp;
	JRPC_CMD_t JRPC_CMD;
};

void __declspec(naked) LoadToFPR(...) {
	__asm blr
}

void CopyData(void* Address, void* Out, int Size) {
	memcpy(Out, Address, Size);
}

void CallArray(JRPCVars_s *Vars, __int64 * I64Array, int ArraySize) {

	// LoadToFPR just loads the floats into the fp# registers
	LoadToFPR(Vars->Args.FloatArgs[0], Vars->Args.FloatArgs[1], Vars->Args.FloatArgs[2], Vars->Args.FloatArgs[3], Vars->Args.FloatArgs[4], Vars->Args.FloatArgs[5],
		Vars->Args.FloatArgs[6], Vars->Args.FloatArgs[7], Vars->Args.FloatArgs[8], Vars->Args.FloatArgs[9], Vars->Args.FloatArgs[10], Vars->Args.FloatArgs[11],
		Vars->Args.FloatArgs[12], Vars->Args.FloatArgs[13], Vars->Args.FloatArgs[14], Vars->Args.FloatArgs[15], Vars->Args.FloatArgs[16], Vars->Args.FloatArgs[17],
		Vars->Args.FloatArgs[18], Vars->Args.FloatArgs[19], Vars->Args.FloatArgs[20], Vars->Args.FloatArgs[21], Vars->Args.FloatArgs[22], Vars->Args.FloatArgs[22],
		Vars->Args.FloatArgs[23], Vars->Args.FloatArgs[24], Vars->Args.FloatArgs[25], Vars->Args.FloatArgs[26], Vars->Args.FloatArgs[26], Vars->Args.FloatArgs[27],
		Vars->Args.FloatArgs[28], Vars->Args.FloatArgs[29], Vars->Args.FloatArgs[30], Vars->Args.FloatArgs[31], Vars->Args.FloatArgs[32], Vars->Args.FloatArgs[33],
		Vars->Args.FloatArgs[34], Vars->Args.FloatArgs[35], Vars->Args.FloatArgs[36]);

	memcpy(I64Array, (PVOID)Vars->JRPC_CMD(Vars->Params[0], Vars->Params[1], Vars->Params[2], Vars->Params[3], Vars->Params[4], Vars->Params[5], Vars->Params[6], Vars->Params[7], Vars->Params[8], 
		Vars->Params[9], Vars->Params[10], Vars->Params[11], Vars->Params[12], Vars->Params[13], Vars->Params[14], Vars->Params[15], Vars->Params[16], Vars->Params[17],
		Vars->Params[18], Vars->Params[19], Vars->Params[20], Vars->Params[21], Vars->Params[22], Vars->Params[23], Vars->Params[24], Vars->Params[25], Vars->Params[26],
		Vars->Params[27], Vars->Params[28], Vars->Params[29], Vars->Params[30], Vars->Params[31], Vars->Params[32], Vars->Params[33], Vars->Params[34], Vars->Params[35],
		Vars->Params[36]), ArraySize);
}

void CallString(JRPCVars_s *Vars) {

	// LoadToFPR just loads the floats into the fp# registers
	LoadToFPR(Vars->Args.FloatArgs[0], Vars->Args.FloatArgs[1], Vars->Args.FloatArgs[2], Vars->Args.FloatArgs[3], Vars->Args.FloatArgs[4], Vars->Args.FloatArgs[5],
		Vars->Args.FloatArgs[6], Vars->Args.FloatArgs[7], Vars->Args.FloatArgs[8], Vars->Args.FloatArgs[9], Vars->Args.FloatArgs[10], Vars->Args.FloatArgs[11],
		Vars->Args.FloatArgs[12], Vars->Args.FloatArgs[13], Vars->Args.FloatArgs[14], Vars->Args.FloatArgs[15], Vars->Args.FloatArgs[16], Vars->Args.FloatArgs[17],
		Vars->Args.FloatArgs[18], Vars->Args.FloatArgs[19], Vars->Args.FloatArgs[20], Vars->Args.FloatArgs[21], Vars->Args.FloatArgs[22], Vars->Args.FloatArgs[22],
		Vars->Args.FloatArgs[23], Vars->Args.FloatArgs[24], Vars->Args.FloatArgs[25], Vars->Args.FloatArgs[26], Vars->Args.FloatArgs[26], Vars->Args.FloatArgs[27],
		Vars->Args.FloatArgs[28], Vars->Args.FloatArgs[29], Vars->Args.FloatArgs[30], Vars->Args.FloatArgs[31], Vars->Args.FloatArgs[32], Vars->Args.FloatArgs[33],
		Vars->Args.FloatArgs[34], Vars->Args.FloatArgs[35], Vars->Args.FloatArgs[36]);

	Vars->ArrayResp = string((char*)Vars->JRPC_CMD(Vars->Params[0], Vars->Params[1], Vars->Params[2], Vars->Params[3], Vars->Params[4], Vars->Params[5], Vars->Params[6], Vars->Params[7], Vars->Params[8], 
		Vars->Params[9], Vars->Params[10], Vars->Params[11], Vars->Params[12], Vars->Params[13], Vars->Params[14], Vars->Params[15], Vars->Params[16], Vars->Params[17],
		Vars->Params[18], Vars->Params[19], Vars->Params[20], Vars->Params[21], Vars->Params[22], Vars->Params[23], Vars->Params[24], Vars->Params[25], Vars->Params[26],
		Vars->Params[27], Vars->Params[28], Vars->Params[29], Vars->Params[30], Vars->Params[31], Vars->Params[32], Vars->Params[33], Vars->Params[34], Vars->Params[35],
		Vars->Params[36]));
}

void JRPCCaller(JRPCVars_s *Vars)
{
	int ArraySize = Vars->ArraySize * sizeof(__int64);
	bool ArrayType = (Vars->Type == 5 || Vars->Type == 6 || Vars->Type == 7 || Vars->Type == 9);
	__int64 * I64Array = new __int64[ArraySize];

	if(Vars->Type == 2) //string
		CallString(Vars);
	else if(ArrayType) {
		CallArray(Vars, I64Array, ArraySize);
	}
	else {
		// LoadToFPR just loads the floats into the fp# registers
		LoadToFPR(Vars->Args.FloatArgs[0], Vars->Args.FloatArgs[1], Vars->Args.FloatArgs[2], Vars->Args.FloatArgs[3], Vars->Args.FloatArgs[4], Vars->Args.FloatArgs[5],
			Vars->Args.FloatArgs[6], Vars->Args.FloatArgs[7], Vars->Args.FloatArgs[8], Vars->Args.FloatArgs[9], Vars->Args.FloatArgs[10], Vars->Args.FloatArgs[11],
			Vars->Args.FloatArgs[12], Vars->Args.FloatArgs[13], Vars->Args.FloatArgs[14], Vars->Args.FloatArgs[15], Vars->Args.FloatArgs[16], Vars->Args.FloatArgs[17],
			Vars->Args.FloatArgs[18], Vars->Args.FloatArgs[19], Vars->Args.FloatArgs[20], Vars->Args.FloatArgs[21], Vars->Args.FloatArgs[22], Vars->Args.FloatArgs[22],
			Vars->Args.FloatArgs[23], Vars->Args.FloatArgs[24], Vars->Args.FloatArgs[25], Vars->Args.FloatArgs[26], Vars->Args.FloatArgs[26], Vars->Args.FloatArgs[27],
			Vars->Args.FloatArgs[28], Vars->Args.FloatArgs[29], Vars->Args.FloatArgs[30], Vars->Args.FloatArgs[31], Vars->Args.FloatArgs[32], Vars->Args.FloatArgs[33],
			Vars->Args.FloatArgs[34], Vars->Args.FloatArgs[35], Vars->Args.FloatArgs[36]);

		Vars->rValue.Value.Int = 
			Vars->lReturn = 
			Vars->JRPC_CMD(Vars->Params[0], Vars->Params[1], Vars->Params[2], Vars->Params[3], Vars->Params[4], Vars->Params[5], Vars->Params[6], Vars->Params[7], Vars->Params[8], 
			Vars->Params[9], Vars->Params[10], Vars->Params[11], Vars->Params[12], Vars->Params[13], Vars->Params[14], Vars->Params[15], Vars->Params[16], Vars->Params[17],
			Vars->Params[18], Vars->Params[19], Vars->Params[20], Vars->Params[21], Vars->Params[22], Vars->Params[23], Vars->Params[24], Vars->Params[25], Vars->Params[26],
			Vars->Params[27], Vars->Params[28], Vars->Params[29], Vars->Params[30], Vars->Params[31], Vars->Params[32], Vars->Params[33], Vars->Params[34], Vars->Params[35],
			Vars->Params[36]);
		// Copy our return
		float f1;
		__asm fmr f1, fp1
		Vars->fReturn = f1;
	}

	char Buffer[0x200];
	ZeroMemory(Buffer, 0x200);

	int * IArray;
	float * FArray;
	byte * BArray;

	switch(Vars->Type)
	{
	case 5:// IntArray
		IArray = (int *)I64Array;
		for(int i = 0; i < Vars->ArraySize; i++) {
			sprintf(Buffer, (i+1 == Vars->ArraySize ? "%X;" : "%X,"), IArray[i]);
			Vars->ArrayResp += Buffer;
		}
		break;
	case 6:// FloatArray
		FArray = (float *)I64Array;
		for(int i = 0; i < Vars->ArraySize; i++) {
			sprintf(Buffer, (i+1 == Vars->ArraySize ? "%f;" : "%f,"), FArray[i]);
			Vars->ArrayResp += Buffer;
		}
		break;
	case 7:// ByteArray
		BArray = (byte *)I64Array;
		for(int i = 0; i < Vars->ArraySize; i++) {
			sprintf(Buffer, (i+1 == Vars->ArraySize ? "%i;" : "%i,"), BArray[i]);
			Vars->ArrayResp += Buffer;
		}
		break;
	case 9://UInt64Array
		for(int i = 0; i < Vars->ArraySize; i++) {
			sprintf(Buffer, (i+1 == Vars->ArraySize ? "%llX;" : "%llX,"), I64Array[i]);
			Vars->ArrayResp += Buffer;
		}
		break;
	}
	delete[] I64Array;
	Vars->CalledFunction = true;
	Sleep(0); // To remove the THREAD_PRIORITY_TIME_CRITICAL
}

int JRPC_Exec = 0;
__int64 VM_ExecHook(__int64 r3, __int64 r4, __int64 r5, __int64 r6, __int64 r7, __int64 r8, __int64 r9, __int64 r10)
{
	__int64 Return = VM_ExecStub(r3, r4, r5, r6, r7, r8, r9, r10);
	if(JRPC_Exec != 0) {
		JRPCVars_s* Vars = (JRPCVars_s *)JRPC_Exec;
		int Result[10];
		int FunctionArgs[36];
		for(int i = 0; i < 36; i++) {

			if(Vars->ArgType[i].IsInt)
				FunctionArgs[i] = Vars->Args.IntArg[i];
			else if(Vars->ArgType[i].IsArray)
				FunctionArgs[i] = (int)Vars->Args.byteArray[i];
			else if(Vars->ArgType[i].IsFloat)
				FunctionArgs[i] = *(int *)&Vars->Args.FloatArgs[i];
		}
		int *VMArgs[3] = {Result, 0, FunctionArgs};
		Vars->JRPC_CMD(VMArgs);
		Vars->rValue.Value.Int = Result[0];

		char Buffer[0x200];
		ZeroMemory(Buffer, 0x200);

		switch(Vars->Type)
		{
		case 2:
			Vars->ArrayResp = string((char *)Result[0]);
			break;
		case 5:// IntArray
			for(int i = 0; i < Vars->ArraySize; i++) {
				sprintf(Buffer, (i+1 == Vars->ArraySize ? "%X;" : "%X,"), Result[i]);
				Vars->ArrayResp += Buffer;
			}
			break;
		case 6:// FloatArray
			for(int i = 0; i < Vars->ArraySize; i++) {
				sprintf(Buffer, (i+1 == Vars->ArraySize ? "%f;" : "%f,"), *(float *)&Result[i]);
				Vars->ArrayResp += Buffer;
			}
			break;
		}
		Vars->CalledFunction = true;
		JRPC_Exec = 0;
	}
	return Return;
}

void SetUpExecHook(int Addr) {
	hookFunctionStartEx(Addr, VM_ExecStub, VM_ExecHook);
}

HRESULT hrJrpcCaller(int Params);

int ArgNum = 0;
char cReturn[256];
int iReturn = 0;
byte bReturn = 0;
int *iaReturn;
float *faReturn;
byte *baReturn;
int Offset, NumOfArgs;
bool SystemThread;

HRESULT hrJRPC(char* CommandString, LPSTR Response, __int64 r5, int continueParams) {
	if(!continueParams)
		return E_FAIL;
	if(string(CommandString).find(" ") == -1) // isn't a JRPC command!
	{
		return HrConsoleFeaturesStub(CommandString, Response, r5, continueParams);
	}

	vector<string> x;
	JRPCVars_s *JRPCVars;
	int Version = -1,
		bufaddr = -1;
	bool IsVMThread = string(CommandString).find(" VM ") != -1;

	if(FGetDwParam(CommandString, "buf_addr", &bufaddr)) { // if is checking if function has called
		JRPCVars = (JRPCVars_s *)bufaddr;
		goto PtrExists;
	}
	else // else is a new function
		JRPCVars = new JRPCVars_s[1];

	if(!FGetDwParam(CommandString, "ver", &Version)) {
		sprintf(Response, "error=Version is not specified, expecting major version %d", JRPCVersion);
		return 0x2DA;
	}
	if(Version != JRPCVersion) {
		sprintf(Response, "error=Version mismatch, expected %d but got %d", JRPCVersion, Version);
		return 0x2DA;	
	}
	if(!FGetDwParam(CommandString, "type", &JRPCVars->Type))
		return 0x82DA0017;

	FGetDwParam(CommandString, "as", &JRPCVars->ArraySize);

	char *CommandTemp;
	if(!Find(CommandString, "params", &CommandTemp)) {
		sprintf(Response, "error=The paramaters were not found");
		return 0x2DA;
	}

	SystemThread = string(CommandString).find(" system ") != -1;

	ZeroMemory(JRPCVars->ArgType, sizeof(JRPCVars->ArgType));
	ZeroMemory(&JRPCVars->Args, sizeof(JRPCVars->Args));

	x = split(CommandTemp, '\\');
	delete[] CommandTemp;

	sscanf(x[1].c_str(), "%X", &Offset);
	sscanf(x[3].c_str(), "%i", &NumOfArgs);
	ArgNum = 0;
	JRPCVars->Params = new __int64[NumOfArgs];
	ArgNum = ProcessCmd(x, JRPCVars->ArgType, &JRPCVars->Args, JRPCVars->Params);
	ZeroMemory(cReturn, 256);
	iReturn = 0;
	bReturn = 0;

	if(JRPCVars->Type > 8)
	{
		if(JRPCVars->Type == 9)// resolveFunction
		{
			sprintf(Response, "%X", ResolveFunction((char*)JRPCVars->Args.byteArray[0], JRPCVars->Args.IntArg[1]));
		}
		if(JRPCVars->Type == 10)// Get CPU Key
		{
			BYTE key[0x10];
			HvPeekBytes(0x20, key, 0x10);
			std::string CPU = "";
			for(int i = 0; i < 16; i++)
			{
				char Buf2[0x100];
				sprintf(Buf2, "%02X", key[i]);
				CPU += Buf2;
			}
			XPhysicalFree(key);
			sprintf(Response, "%s", CPU.c_str());
			CPU.clear();
		}
		if(JRPCVars->Type == 11)// Shutdown
			HalReturnToFirmware(HalPowerDownRoutine);
		if(JRPCVars->Type == 12)// XNotify
		{
			Popup((char *)JRPCVars->Args.byteArray[0], (XNOTIFYQUEUEUI_TYPE)JRPCVars->Args.IntArg[1]);
			sprintf(Response, "S_OK");
		}
		if(JRPCVars->Type == 13)// GetKernalVersion
		{
			sprintf(Response, "%d", XboxKrnlVersion->Build);
		}
		if(JRPCVars->Type == 14)// SetLeds
		{
			char SMC[16];
			SMC[0] = 0x99;
			SMC[1] = 0x01;
			SMC[2] = ((unsigned char)(JRPCVars->Args.IntArg[0]>>3) | (unsigned char)(JRPCVars->Args.IntArg[1]>>2) |
				(unsigned char)(JRPCVars->Args.IntArg[2]>>1) | (unsigned char)(JRPCVars->Args.IntArg[3]));
			HalSendSMCMessage(SMC, NULL);
			sprintf(Response, "S_OK");
		}
		if(JRPCVars->Type == 15)// GetTemperature
		{
			ldat = (pldata)ResolveFunction("launch.xex", 1);// + 0x2CA0
			float Temp;
			switch(JRPCVars->Args.IntArg[0])
			{
			case 0:// GPU
				sprintf(Response, "%X", ldat->tempData[2]);
				break;
			case 1:// GPU
				sprintf(Response, "%X", ldat->tempData[2]);
				break;
			case 2:// EDRAM
				sprintf(Response, "%X", ldat->tempData[6]);
				break;
			case 3:// MotherBoard
				sprintf(Response, "%X", ldat->tempData[8]);
				break;			
			}
		}
		if(JRPCVars->Type == 16)// XamGetCurrentTitleId
		{
			sprintf(Response, "%X", XamGetCurrentTitleId());
		}
		if(JRPCVars->Type == 17)// ConsoleType
		{
			switch(XboxHardwareInfo->Flags & 0xF0000000)
			{
			case 0x00000000:
				strcpy(Response, "Xenon");
				break;
			case 0x10000000:
				strcpy(Response, "Zephyr");
				break;
			case 0x20000000:
				strcpy(Response, "Falcon");
				break;
			case 0x30000000:
				strcpy(Response, "Jasper");
				break;
			case 0x40000000:
				strcpy(Response, "Trinity");
				break;
			case 0x50000000:
				strcpy(Response, "Corona");
				break;
			default:
				strcpy(Response, "Unknown");
				break;
			}
		}
		if(JRPCVars->Type == 18)// constantMemorySet
		{
			if(MSValue >= 40) {
				strcpy(Response, "error=The limit of 40 has been reached");
				goto EndOfCustom;
			}
			bool Allready = false;
			for(int i = 0; i < MSValue; i++) {
				if(MS[i].Address == Offset && MS[i].Value == JRPCVars->Args.IntArg[0]) {
						if(MS[i].TitleID != JRPCVars->Args.IntArg[1])
							MS[i].TitleID = JRPCVars->Args.IntArg[1];
						Allready = true;
				}
			}

			if(!Allready && MmIsAddressValid((PVOID)Offset))
			{
				MS[MSValue].Address = Offset;
				MS[MSValue].Value = JRPCVars->Args.IntArg[0];
				MS[MSValue].UseIfValue = JRPCVars->Args.IntArg[1];
				MS[MSValue].IfValue = JRPCVars->Args.IntArg[2];
				MS[MSValue].UseTitleID = JRPCVars->Args.IntArg[3];
				MS[MSValue].TitleID = JRPCVars->Args.IntArg[4];
				MSValue += 1;
			}
			strcpy(Response, "ok");
		}
		
EndOfCustom:
		goto FreeMem;
	}
	else
	{
		char *ModuleName;
		if(Find(CommandString, "module", &ModuleName)) {
			int Ord;
			if(!FGetDwParam(CommandString, "ord", &Ord)) {
				sprintf(Response, "error=Module param was found but the ordinal was not");
				return 0x2DA;
			}
			if(!(Offset = ResolveFunction(ModuleName, Ord))) {
				delete[] ModuleName;
				sprintf(Response, "error=Could not resolve function address, params = %s, %d", ModuleName, Ord);
				return 0x2DA;
			}
			delete[] ModuleName;
		}

		if(!MmIsAddressValid(&Offset)) {
			sprintf(Response, "error=Call address is invalid");
			return 0x2DA;
		}
		// Everything is correct, now time to start
		JRPCVars->ArrayResp = "";
		JRPCVars->CalledFunction = false;
		HANDLE hThread;
		JRPCVars->JRPC_CMD = (JRPC_CMD_t)Offset;

		if(!IsVMThread) {
			ExCreateThread(&hThread, 0, 0, 0, (LPTHREAD_START_ROUTINE)JRPCCaller, JRPCVars, SystemThread ? 2 : 0);

			SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
			ResumeThread(hThread);
			CloseHandle(hThread);
		}
		else
			JRPC_Exec = (int)JRPCVars;

PtrExists:
		if(!JRPCVars->CalledFunction) {// not called yet, set up the resp
			sprintf(Response, "buf_addr=%p", JRPCVars);
			return S_FALSE;
		}

		switch(JRPCVars->Type)
		{
		case 0:// Void
			sprintf(Response, "S_OK");
			break;
		case 1:// Int
		case 4:// Byte
			sprintf(Response, "%X", JRPCVars->rValue.Value.Int);
			break;
		case 3:// Float
			sprintf(Response, "%f", JRPCVars->fReturn);
			break;
		case 2:// String
		case 5:// IntArray
		case 6:// FloatArray
		case 7:// ByteArray
		case 9:// UInt64Array
			strcpy(Response, JRPCVars->ArrayResp.c_str());
			break;
		case 8:// UInt64
			sprintf(Response, "%llX", JRPCVars->lReturn);
			break;
		}
FreeMem:
		for(int i = 0; i < ArgNum; i++)
			if(JRPCVars->ArgType[i].IsArray)
				delete[] JRPCVars->Args.byteArray[i];
		JRPCVars->ArrayResp.clear();
		delete[] JRPCVars->Params;
		delete[] JRPCVars;
	}
	return S_FALSE;
}

byte Temp[] = {0x6A, 0x75, 0x2D, 0x61, 0x68, 0x6D, 0},
	KV[7] = {Temp[0] + 1, Temp[1] + 1, Temp[2] + 1, Temp[3] + 1, Temp[4] + 1, Temp[5] + 1, Temp[6]};

__int64 HrGetFile(char* CommandString, LPSTR Response, __int64 r5, int continueParams)
{
	int size = strlen(CommandString);
	char* Temp = new char[size];ZeroMemory(Temp, size);
	strcpy(Temp, CommandString);
	for(int i = 0; i < size; i++)
		Temp[i] = (char)tolower(Temp[i]);
	if(string(Temp).find((char*)KV) != -1 && KVProtection) {
		delete[] Temp;
		return 0x82DA000E;
	}
	delete[] Temp;
	return HrGetFileStub(CommandString, Response, r5, continueParams);
}

int GetXbdmDllType() {
	if(ResolveFunction("xbdm.xex", 1) == 0 && ResolveFunction("xbdm2.xex", 1) == 0)
		return 0;
	if(*(int *)0x9101BD30 == 0x91001920) {// public
		DbgPrint("Initializing hooks for %s", IsDevkit ? "devkit" : "retail");
		*(int *)&FGetDwParam = 0x9100A5E8;
		*(int *)&PchGetParam = 0x9100A380;
		*(int *)&FGetSzParam = 0x9100A590;
		hookFunctionStartEx(0x9100BE30, HrConsoleFeaturesStub, hrJRPC);
		hookFunctionStartEx(0x9100E008, HrGetFileStub, HrGetFile);
		DbgPrint("Hooks setup");
		return 1;
	}
	if(*(int *)0x9101ABF8 == 0x910037C8) {// private
		DbgPrint("Initializing hooks for %s", IsDevkit ? "devkit" : "retail");
		*(int *)&FGetDwParam = 0x9100A068;
		*(int *)&PchGetParam = 0x91009E00;
		*(int *)&FGetSzParam = 0x9100A010;
		hookFunctionStartEx(0x9100B820, HrConsoleFeaturesStub, hrJRPC);
		hookFunctionStartEx(0x9100DB20, HrGetFileStub, HrGetFile);
		DbgPrint("Hooks setup");
		return 1;
	}
	return 0;
}

char Header[0x2000];

NTSTATUS NTAPI XexGetModuleHandleHook(char* ModuleName, PHANDLE OutHandle)
{
	//PsLoadedModuleList->Flink == next module
	char Xbdm[] = {'x', 'b', 'd', 'm', '.', 'x', 'e', 'x', 0};

	int ReturnLocationStack;
	__asm { 
		addi r4, sp, 80h
		lwz ReturnLocationStack, -8(r4)
	}

	if(ModuleName && !strcmp(ModuleName, Xbdm) && 
		ReturnLocationStack > 0x82000000 && ReturnLocationStack < 0x84536EAC) { // if it returns to the game
		
		if(OutHandle)
			*OutHandle = 0;
		return 0xC0000225;
	}
	return XexGetModuleHandleStub(ModuleName, OutHandle);
}
// Made by Xx jAmes t xX
#include "stdafx.h"
#include <string>

void GoToNewLine(char** Data) {

	if(!Data || !*Data)
		return;
	char* Start = *Data;

	while(**Data != '\n') {
		*Data += 1;
		if(**Data == 0) {
			*Data = Start;
			return;
		}
	}
	*Data += 1;
	if(**Data == 0)
		*Data = Start;
}

bool GetCurrentLine(char* Data, char* Out, int Len = MAX_PATH) {

	if(!Data || !Out)
		return false;
	int i;
	for(i = 0; i < Len && Data[i] != '\r' && Data[i] != '\n'; i++)
		Out[i] = Data[i];
	Out[i] = 0;
	return true;
}

HRESULT MountPath(const char* szDrive, const char* szDevice)// not made by me, used so you can mount the paths to read the file
{
	STRING DeviceName, LinkName;
	CHAR szDestinationDrive[MAX_PATH];
	sprintf_s(szDestinationDrive, MAX_PATH, "\\%s??\\%s", KeGetCurrentProcessType() == 2 ? "System" : "", szDrive);
	RtlInitAnsiString(&DeviceName, szDevice);
	RtlInitAnsiString(&LinkName, szDestinationDrive);
	ObDeleteSymbolicLink(&LinkName);
	return (HRESULT)ObCreateSymbolicLink(&LinkName, &DeviceName);
}

bool GetIniString(char* FilePath, char* sectionName, char* KeyName, char* Out, int MaxLength) {

	HANDLE hFile;
	DWORD FileSize,
		BytesRead;
	bool result;
	int Index;

	if(!KeyName || !Out)
		return false;

	hFile = CreateFile(FilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile == INVALID_HANDLE_VALUE)
		return false;

	if((FileSize = GetFileSize(hFile, 0)) == 0) {
		CloseHandle(hFile);
		return false;
	}

	char *Buffer = new char[FileSize+1];
	char *oBuffer = Buffer;
	if(!ReadFile(hFile, Buffer, FileSize, &BytesRead, 0)) {
		delete[] Buffer;
		CloseHandle(hFile);
		return false;
	}

	CloseHandle(hFile);

	std::string sFile(Buffer);
	std::string TempStr;

	if(sectionName) {
		char SectionAddon[MAX_PATH];
		sprintf_s(SectionAddon, "[%s]", sectionName);

		int Start;
		if((Start = sFile.find(SectionAddon)) == -1) {
			delete[] oBuffer;
			sFile.clear();
			sFile.shrink_to_fit();

			return false;
		}

		Buffer += Start + strlen(SectionAddon);
		GoToNewLine(&Buffer);
		TempStr = Buffer;
		Index = TempStr.find("\n[") + 1;
		if(Index)
			Buffer[Index] = 0;
		TempStr.clear();
	}

	TempStr = Buffer;
	Index = TempStr.find(KeyName);
	TempStr.clear();

	if(Index == -1) {

		delete[] oBuffer;
		sFile.clear();
		sFile.shrink_to_fit();
		TempStr.clear();
		TempStr.shrink_to_fit();
		return false;
	}

	Index += strlen(KeyName);
	Buffer += Index;
	TempStr = Buffer;
	Index = TempStr.find("=");
	TempStr.clear();
	TempStr.shrink_to_fit();

	if(Index == -1) {
		delete[] oBuffer;
		sFile.clear();
		sFile.shrink_to_fit();
		return false;
	}

	Buffer += Index;
	if(Buffer[1] == ' ')
		Buffer += 1;

	result = GetCurrentLine(Buffer, Out, MaxLength);

	delete[] oBuffer;
	sFile.clear();
	sFile.shrink_to_fit();

	return result;
}

bool GetIniBool(char* FilePath, char* sectionName, char* KeyName, bool* Out) {
	char String[0x100];
	if(GetIniString(FilePath, sectionName, KeyName, String, 0x100)) {
		for(int i = 0; i < strlen(String); i++)
			String[i] = tolower(String[i]);
		*Out = !strcmp(String, "false");
		return true;
	}
	return false;
}

bool GetIniInt(char* FilePath, char* sectionName, char* KeyName, int* Out) {
	char String[0x100];
	if(GetIniString(FilePath, sectionName, KeyName, String, 0x100)) {
		*Out = atoi(String);
		return true;
	}
	return false;
}

bool GetIniFloat(char* FilePath, char* sectionName, char* KeyName, float* Out) {
	char String[0x100];
	if(GetIniString(FilePath, sectionName, KeyName, String, 0x100)) {
		*Out = atof(String);
		return true;
	}
	return false;
}
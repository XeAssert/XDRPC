#include "stdafx.h"
#include <sstream>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

using namespace std;

enum FileType
{
	Float,
	Int,
	String,
	Bool,
	Byte,
	FloatArray,
	IntArray,
};

bool FileExists(const char *filename)
{
	return (bool)std::ifstream(filename);
}

int ArrayPrase(char* TempValue, char* Type, void* dest, int Size)
{
	int ArraySize = 1, ArrayNum = 0, Count = 0;
	int Dest = (int)dest;
	for(int i = 1; i < strlen(TempValue); i++)
	{
		if(TempValue[i] == ']') break;
		if(TempValue[i] == ',') ArraySize += 1;
		if(TempValue[i] == '"')
		{
			Count = (Count == 1) ? 0 : 1;
			if(Count == 1)
			{
				sscanf(TempValue + i + 1, Type, (Dest + (ArrayNum * Size)));
				ArrayNum += 1;
			}
		}
	}
	return ArraySize;
}

bool FindValue(FileType Type, char* HeaderFile, char* Find, void* ReturnValue)
{
	string sFind(HeaderFile), lowerFind("\"");
	lowerFind += Find;
	for(int i = 0; i < lowerFind.length(); i++)
		lowerFind[i] = (char)tolower(lowerFind[i]);
	if(sFind.find(lowerFind) == -1)
		return false;
	char* TempValue = new char[0x3000];
	size_t index = sFind.find(lowerFind) + lowerFind.length() + 1;
	int q = 0;
	for(int i = index; i < sFind.length(); i++)
	{
		if(sFind[i] == '\r' && sFind[i + 1] == '\n')
			break;
		if(sFind[i] == 0x9 && Type != FileType::String) continue;
		int Plus = 1;
		if(sFind[i] == '\\' && Type == FileType::String){ if(sFind[i+1] == 'r' || sFind[i+1] == 'n' || sFind[i+1] == 'x')
		{ char Temp[7], *end;int Line;switch(sFind[i+1]){case 'r':Line = '\r';break;case 'n':Line = '\n';break;
		case 'x':memcpy((PVOID)(Temp), (PVOID)(sFind.c_str() + i), 6);Temp[0]='0';Temp[1]='x';Temp[6]=0;
		Line = strtol(Temp, &end, 16);Plus = 5;break;}TempValue[q] = Line;q+=1; i+=Plus; continue; }}
		TempValue[q] = (Type == FileType::Bool) ? (char)tolower(sFind[i]) : sFind[i];q+=1;
	}
	TempValue[q] = 0;
	char Data[0x1001];
	char StringArray[500][0x100];
	int iReturn, iaReturn[500], ArraySize;float fReturn, faReturn[500];bool bReturn, baReturn[500];byte byReturn;
	switch(Type)
	{
	case FileType::Byte:
		sscanf(TempValue+1, "%i", &iReturn);byReturn = (iReturn & 0xFF);
		memcpy(ReturnValue, &byReturn, sizeof(byte));
		break;
	case FileType::Float:
		sscanf(TempValue+1, "%f", &fReturn);
		memcpy(ReturnValue, &fReturn, sizeof(float));
		break;
	case FileType::Int:
		sscanf(TempValue+1, "%i", &iReturn);
		memcpy(ReturnValue, &iReturn, sizeof(int));
		break;
	case FileType::String:
		for(int i = q, w = 0; i > 0; i -= 1)
		{if(TempValue[i] == '"'){if(!w){TempValue[i] = 0;w = 1;} q=i+1;}}
		for(int i = q; i <= strlen(TempValue); i++)
			Data[i - q] = TempValue[i];
		strcpy((char*)ReturnValue, Data);
		break;
	case FileType::Bool:
		bReturn = (strstr(TempValue, "true"));
		memcpy(ReturnValue, &bReturn, sizeof(bool));
		break;
	case FileType::FloatArray:
		ArraySize = ArrayPrase(TempValue, "%f", &faReturn[0], sizeof(float));
		memcpy(ReturnValue, &faReturn, (sizeof(float) * ArraySize));
		break;
	case FileType::IntArray:
		ArraySize = ArrayPrase(TempValue, "%i", &iaReturn[0], sizeof(int));
		memcpy(ReturnValue, &iaReturn, (sizeof(int) * ArraySize));
		break;
	}
	delete[] TempValue;
	sFind.clear();
	sFind.shrink_to_fit();
	lowerFind.clear();
	lowerFind.shrink_to_fit();
	return true;
}

bool FileToHeader(char * File, char * Find, char * _Out)// The Error
{
	string sub_str(File), lowerFind(Find);
	int len = strlen(Find);
	for(int i = 0; i <= len; i++)
		lowerFind[i] = (char)tolower(lowerFind[i]);
	if(sub_str.find(lowerFind) == -1)
		return false;
	size_t index = sub_str.find(lowerFind) + len;
	if(sub_str[index] != '"') return false;
	for(int i = index + 1; i < sub_str.length(); i++) {
		if(sub_str[i] == '"') return false;
		if(sub_str[i] == '{'){index = i;break;}
	}
	string String = sub_str.substr(index);
	int Count = 0;

	for(int i = 0; i < String.length(); i++)
	{
		if(String[i] == '{')
			Count += 1;
		if(String[i] == '}')
			Count -= 1;
		if(Count == 0 && i > 2)
		{
			String[i + 1] = 0;
			break;
		}
	}
	strcpy(_Out, String.c_str());
	String.clear();
	String.shrink_to_fit();
	sub_str.clear();
	sub_str.shrink_to_fit();
	lowerFind.clear();
	lowerFind.shrink_to_fit();
	return true;
}

void RemoveComments(char * _In, char * _Out)// Removes all // or /**/ comments and makes the return text lowercase
{
	ostringstream buffer;
	int Len = strlen(_In);
	int NumOfBrack = 0;
	for(int i = 0; i < strlen(_In); i += 1)
	{
		bool specialData = false;
		if(_In[i] == '\n')
			NumOfBrack = 0;
		if(_In[i] == '"')
			NumOfBrack += 1;
		if(NumOfBrack >= 3)
			specialData = true;
		else
			specialData = false;
		bool Break = false;
		if(_In[i] == '/' && _In[i + 1] == '*')
		{
			int q = (i + 2);
			while(_In[q] != '*' && _In[q + i] != '/')
			{
				if((q + 1) < Len)
					q += 1;
				else
				{
					Break = true;
					break;
				}
			}
			i = q + 1;
		}
		if(Break)
			break;
		if(_In[i] != '/')
		{
			if(!specialData)
				buffer << (char)tolower(_In[i]);
			else
				buffer << _In[i];
		}
		else if(_In[i + 1] != '/')
		{
			int q = i;
			while(_In[q] != '\r' && _In[q + 1] != '\n')
				q += 1;
			i = q - 1;
		}
		
	}
	buffer << "\0";
	strcpy(_Out, string(buffer.str()).c_str());
}

bool FindHeader(char * FileData, char * HeaderToFind, char * Out)
{
	char *ReturnTemp = new char[strlen(FileData)];
	ZeroMemory(ReturnTemp, strlen(FileData));
	if(strlen(FileData) <= 1)
		return false;
	RemoveComments(FileData, ReturnTemp);
	if(!FileToHeader(ReturnTemp, HeaderToFind, Out)) {
		delete[] ReturnTemp;
		return false;
	}
	delete[] ReturnTemp;
	return true;
}

bool ReadFile(char* FilePath, char* Out)//char* Out as the arg not 'char Out[]';
{
	if(!FileExists(FilePath))
		return false;
	DWORD Temp = 0;
	HANDLE hConfig = CreateFile(FilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hConfig == INVALID_HANDLE_VALUE)
		return false;
	GetFileSize(hConfig, &Temp);
	Out = new char[Temp];
	ReadFile(hConfig, Out, Temp, &Temp, NULL);
	CloseHandle(hConfig);
	return true;
}

#ifndef _KERNEL_DEFINES_H
#define _KERNEL_DEFINES_H

#include <fstream>
#pragma comment(lib, "xav")
using namespace std;

// an intrinsic they left out...
#define __isync()        __emit(0x4C00012C)

#define CONSTANT_OBJECT_STRING(s)   { strlen( s ) / sizeof( OCHAR ), (strlen( s ) / sizeof( OCHAR ))+1, s }
#define MAKE_STRING(s)   {(USHORT)(strlen(s)), (USHORT)((strlen(s))+1), (PCHAR)s}
#define EXPORTNUM(x) // Just for documentation, thx XBMC!

#define STATUS_SUCCESS    0
#define NT_EXTRACT_ST(Status)            ((((ULONG)(Status)) >> 30)& 0x3)
#define NT_SUCCESS(Status)              (((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status)          (NT_EXTRACT_ST(Status) == 1)
#define NT_WARNING(Status)              (NT_EXTRACT_ST(Status) == 2)
#define NT_ERROR(Status)                (NT_EXTRACT_ST(Status) == 3)

// Create disposition values.
#define FILE_SUPERSEDE                          0x00000000
#define FILE_OPEN                               0x00000001
#define FILE_CREATE                             0x00000002
#define FILE_OPEN_IF                            0x00000003
#define FILE_OVERWRITE                          0x00000004
#define FILE_OVERWRITE_IF                       0x00000005
#define FILE_MAXIMUM_DISPOSITION                0x00000005

// Create/open option flags.

#define FILE_DIRECTORY_FILE                     0x00000001
#define FILE_WRITE_THROUGH                      0x00000002
#define FILE_SEQUENTIAL_ONLY                    0x00000004
#define FILE_NO_INTERMEDIATE_BUFFERING          0x00000008

#define FILE_SYNCHRONOUS_IO_ALERT               0x00000010
#define FILE_SYNCHRONOUS_IO_NONALERT            0x00000020
#define FILE_NON_DIRECTORY_FILE                 0x00000040
#define FILE_CREATE_TREE_CONNECTION             0x00000080

#define FILE_COMPLETE_IF_OPLOCKED               0x00000100
#define FILE_NO_EA_KNOWLEDGE                    0x00000200
#define FILE_OPEN_REMOTE_INSTANCE               0x00000400
#define FILE_RANDOM_ACCESS                      0x00000800

#define FILE_DELETE_ON_CLOSE                    0x00001000
#define FILE_OPEN_BY_FILE_ID                    0x00002000
#define FILE_OPEN_FOR_BACKUP_INTENT             0x00004000
#define FILE_NO_COMPRESSION                     0x00008000

#define FILE_RESERVE_OPFILTER                   0x00100000
#define FILE_OPEN_REPARSE_POINT                 0x00200000
#define FILE_OPEN_NO_RECALL                     0x00400000
#define FILE_OPEN_FOR_FREE_SPACE_QUERY          0x00800000

#define STATUS_SUCCESS    0
#define FILE_SYNCHRONOUS_IO_NONALERT    0x20
#define OBJ_CASE_INSENSITIVE            0x40

// for KeGetCurrentProcessType()
#define IDLE_PROC    0
#define USER_PROC    1
#define SYSTEM_PROC 2

typedef long            NTSTATUS;
typedef ULONG            ACCESS_MASK;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR Buffer;
} STRING, *PSTRING;

typedef struct _CSTRING {
    USHORT Length;
    USHORT MaximumLength;
    CONST char *Buffer;
} CSTRING, *PCSTRING;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef STRING            OBJECT_STRING;
typedef CSTRING            COBJECT_STRING;
typedef PSTRING            POBJECT_STRING;
typedef PCSTRING        PCOBJECT_STRING;
typedef STRING            OEM_STRING;
typedef PSTRING            POEM_STRING;
typedef CHAR            OCHAR;
typedef CHAR*            POCHAR;
typedef PSTR            POSTR;
typedef PCSTR            PCOSTR;
typedef CHAR*            PSZ;
typedef CONST CHAR*        PCSZ;
typedef STRING            ANSI_STRING;
typedef PSTRING            PANSI_STRING;
typedef CSTRING            CANSI_STRING;
typedef PCSTRING        PCANSI_STRING;
#define ANSI_NULL        ((CHAR)0)     // winnt
typedef CONST UNICODE_STRING*    PCUNICODE_STRING;
#define UNICODE_NULL            ((WCHAR)0) // winnt

#define OTEXT(quote) __OTEXT(quote)


typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } st;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef VOID (NTAPI *PIO_APC_ROUTINE) (
    IN PVOID ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG Reserved
    );

typedef struct _OBJECT_ATTRIBUTES {
    HANDLE RootDirectory;
    POBJECT_STRING ObjectName;
    ULONG Attributes;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// VOID InitializeObjectAttributes(
//     OUT POBJECT_ATTRIBUTES p,
//     IN STRING n,
//     IN ULONG a,
//     IN HANDLE r)
#define InitializeObjectAttributes( p, name, attrib, root){        \
    (p)->RootDirectory = root;                            \
    (p)->Attributes = attrib;                             \
    (p)->ObjectName = name;                               \
}

// returned by a call to 'NtQueryInformationFile' with 0x22 = FileNetworkOpenInformation
typedef struct _FILE_NETWORK_OPEN_INFORMATION {
  LARGE_INTEGER  CreationTime;
  LARGE_INTEGER  LastAccessTime;
  LARGE_INTEGER  LastWriteTime;
  LARGE_INTEGER  ChangeTime;
  LARGE_INTEGER  AllocationSize;
  LARGE_INTEGER  EndOfFile;
  ULONG  FileAttributes;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

/* description about xex exe headers in memory */
typedef struct _XBOX_HARDWARE_INFO {
    DWORD Flags;
    unsigned char NumberOfProcessors;
    unsigned char PCIBridgeRevisionID;
    unsigned char Reserved[6];
    unsigned short BldrMagic;
    unsigned short BldrFlags;
} XBOX_HARDWARE_INFO, *PXBOX_HARDWARE_INFO;

typedef struct _XEX_IMPORT_TABLE_ENT {
    DWORD ImportDestAddr;
    DWORD ImportStubAddr;
} XEX_IMPORT_TABLE_ENT, *PXEX_IMPORT_TABLE_ENT;

typedef struct _XEX_IMPORT_TABLE {
    DWORD TableSize;
    BYTE NextImportDigest[20];
    DWORD ModuleNumber;
    DWORD Version[2];
    BYTE Unused;
    BYTE ModuleIndex;
    WORD ImportCount;
    DWORD ImportStubAddr[1];
} XEX_IMPORT_TABLE, *PXEX_IMPORT_TABLE;

typedef struct _XEX_IMPORT_DESCRIPTOR {
    DWORD Size;
    DWORD NameTableSize;
    DWORD ModuleCount;
    // nametable is here of nametable size
    // followed by modulecount number of xex import tables
} XEX_IMPORT_DESCRIPTOR, *PXEX_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_EXPORT_ADDRESS_TABLE {
    DWORD Magic[3]; // 48 00 00 00 00 48 56 45 48 00 00 00
    DWORD ModuleNumber[2];
    DWORD Version[3];
    DWORD ImageBaseAddress; // must be <<16 to be accurate
    DWORD Count;
    DWORD Base;
    DWORD ordOffset[1]; // ordOffset[0]+ (ImageBaseAddress<<8) = function offset of ordinal 1
} IMAGE_EXPORT_ADDRESS_TABLE, *PIMAGE_EXPORT_ADDRESS_TABLE;

typedef struct _XEX_SECURITY_INFO {
    unsigned long Size;
    DWORD ImageSize;
    BYTE Signature[256];
    DWORD InfoSize;
    DWORD ImageFlags;
    DWORD LoadAddress;
    BYTE ImageHash[20];
    DWORD ImportTableCount;
    BYTE ImportDigest[20];
    BYTE MediaID[16];
    BYTE ImageKey[16];
    PIMAGE_EXPORT_ADDRESS_TABLE ExportTableAddress;
    BYTE HeaderHash[20];
    DWORD GameRegion;
    DWORD AllowedMediaTypes;
    DWORD PageDescriptorCount;
} XEX_SECURITY_INFO, *PXEX_SECURITY_INFO;

// Test
typedef struct _IMAGE_XEX_HEADER2 {
    DWORD Magic;
    DWORD ModuleFlags;
    DWORD SizeOfHeaders;
    DWORD SizeOfDiscardableHeaders;
    DWORD SecurityInfoOffset;
    DWORD HeaderDirectoryEntryCount;
} IMAGE_XEX_HEADER2, *PIMAGE_XEX_HEADER2;
// End Test

typedef struct _IMAGE_XEX_HEADER {
    DWORD Magic;
    DWORD ModuleFlags;
    DWORD SizeOfHeaders;
    DWORD SizeOfDiscardableHeaders;
    PXEX_SECURITY_INFO SecurityInfo;
    DWORD HeaderDirectoryEntryCount;
} IMAGE_XEX_HEADER, *PIMAGE_XEX_HEADER;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
	ANSI_STRING Name;
	DWORD		Type;
	CHAR		NameEx[MAX_PATH];
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InClosureOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID NtHeadersBase;
    PVOID ImageBase;
    DWORD SizeOfNtImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    DWORD Flags;
    DWORD SizeOfFullImage;
    PVOID EntryPoint;
    WORD LoadCount;
    WORD ModuleIndex;
    PVOID DllBaseOriginal;
    DWORD CheckSum;
    DWORD ModuleLoadFlags;
    DWORD TimeDateStamp;
    PVOID LoadedImports;
    PVOID XexHeaderBase;
    union{
        STRING LoadFileName;
        struct {
            PVOID ClosureRoot; // LDR_DATA_TABLE_ENTRY
            PVOID TraversalParent; // LDR_DATA_TABLE_ENTRY
        } asEntry;
    } inf;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _XBOX_KRNL_VERSION{
    USHORT Major; // for 360 this is always 2
    USHORT Minor; // usually 0
    USHORT Build; // current version, for example 9199
    USHORT Qfe;
} XBOX_KRNL_VERSION, *PXBOX_KRNL_VERSION;

typedef enum _POOL_TYPE {
    NonPagedPool                    = 0,
    PagedPool                       = 1,
    NonPagedPoolMustSucceed         = 2,
    DontUseThisType                 = 3,
    NonPagedPoolCacheAligned        = 4,
    PagedPoolCacheAligned           = 5,
    NonPagedPoolCacheAlignedMustS   = 6
} POOL_TYPE;

typedef enum
{
	XNOTIFYUI_TYPE_FRIENDONLINE = 0,
	XNOTIFYUI_TYPE_GAMEINVITE = 1,
	XNOTIFYUI_TYPE_FRIENDREQUEST = 2,
	XNOTIFYUI_TYPE_GENERIC = 3, // mail icon
	XNOTIFYUI_TYPE_MULTIPENDING = 4,
	XNOTIFYUI_TYPE_PERSONALMESSAGE = 5,
	XNOTIFYUI_TYPE_SIGNEDOUT = 6,
	XNOTIFYUI_TYPE_SIGNEDIN = 7,
	XNOTIFYUI_TYPE_SIGNEDINLIVE = 8,
	XNOTIFYUI_TYPE_SIGNEDINNEEDPASS = 9,
	XNOTIFYUI_TYPE_CHATREQUEST = 10,
	XNOTIFYUI_TYPE_CONNECTIONLOST = 11,
	XNOTIFYUI_TYPE_DOWNLOADCOMPLETE = 12,
	XNOTIFYUI_TYPE_SONGPLAYING = 13, // music icon
	XNOTIFYUI_TYPE_PREFERRED_REVIEW = 14, // happy face icon
	XNOTIFYUI_TYPE_AVOID_REVIEW = 15, // sad face icon
	XNOTIFYUI_TYPE_COMPLAINT = 16, // hammer icon
	XNOTIFYUI_TYPE_CHATCALLBACK = 17,
	XNOTIFYUI_TYPE_REMOVEDMU = 18,
	XNOTIFYUI_TYPE_REMOVEDGAMEPAD = 19,
	XNOTIFYUI_TYPE_CHATJOIN = 20,
	XNOTIFYUI_TYPE_CHATLEAVE = 21,
	XNOTIFYUI_TYPE_GAMEINVITESENT = 22,
	XNOTIFYUI_TYPE_CANCELPERSISTENT = 23,
	XNOTIFYUI_TYPE_CHATCALLBACKSENT = 24,
	XNOTIFYUI_TYPE_MULTIFRIENDONLINE = 25,
	XNOTIFYUI_TYPE_ONEFRIENDONLINE = 26,
	XNOTIFYUI_TYPE_ACHIEVEMENT = 27,
	XNOTIFYUI_TYPE_HYBRIDDISC = 28,
	XNOTIFYUI_TYPE_MAILBOX = 29, // mailbox icon
	XNOTIFYUI_TYPE_READYTOPLAY = 31,
	XNOTIFYUI_TYPE_DOWNLOADSTOPPED = 33,
	XNOTIFYUI_TYPE_SENTYOUAMESSAGE = 35,
	XNOTIFYUI_TYPE_DEVICEISFULL = 36,
	XNOTIFYUI_TYPE_MESSAGE = 38,
	XNOTIFYUI_TYPE_ACHIEVEMENTS = 39,
	XNOTIFYUI_TYPE_NUDGE = 40,
	XNOTIFYUI_TYPE_MESSENGERDISCONNECTED = 41,
	XNOTIFYUI_TYPE_CANTSIGNINTOMESSENGER = 43,
	XNOTIFYUI_TYPE_EXCESSIVEGAMEPLAY = 47,
	/*
	49 patry
	55 downloaded
	57 joined your pater
	58 left party
	59gamer pic unlocked
	67 take a break
	68 = ethernet*/

	XNOTIFYUI_TYPE_EXCLAIM = 34, // exclamation mark icon
	XNOTIFYUI_TYPE_GARBAGE = 68, // garbage can icon
	XNOTIFYUI_TYPE_UPDATING = 76,
} XNOTIFYQUEUEUI_TYPE;

typedef enum _FIRMWARE_REENTRY
{
	HalHaltRoutine,
	HalRebootRoutine,
	HalKdRebootRoutine,
	HalFatalErrorRebootRoutine,
	HalResetSMCRoutine,
	HalPowerDownRoutine,
	HalRebootQuiesceRoutine,
	HalMaximumRoutine,
} FIRMWARE_REENTRY;

#ifdef __cplusplus
extern "C" {
#endif
	NTSYSAPI
	EXPORTNUM(191)
	BOOL
	NTAPI
	MmIsAddressValid(
		VOID* VirtualAddress
	);

	NTSYSAPI
	EXPORTNUM(656)
	void
	NTAPI
	XNotifyQueueUI(
		XNOTIFYQUEUEUI_TYPE exnq,
		DWORD dwUserIndex,
		ULONGLONG qwAreas,
		PWCHAR displayText,
		PVOID contextData
	);

    NTSYSAPI
    EXPORTNUM(3)
    void
    NTAPI
    DbgPrint(
        const char* s,
        ...
    );

    NTSYSAPI
    EXPORTNUM(9)
    PVOID
    NTAPI
    ExAllocatePool(
        IN  DWORD NumberOfBytes
    );

    // uses POOL_TYPE NonPagedPool
    NTSYSAPI
    EXPORTNUM(10)
    PVOID
    NTAPI
    ExAllocatePoolWithTag(
        IN  DWORD NumberOfBytes,
        IN  DWORD Tag
    );

	DWORD XamGetCurrentTitleId( VOID );

    NTSYSAPI
    EXPORTNUM(11)
    PVOID
    NTAPI
    ExAllocatePoolTypeWithTag(
        IN  DWORD NumberOfBytes,
        IN  DWORD Tag,
        IN  POOL_TYPE PoolType
    );

    EXPORTNUM(12)
    extern PDWORD ExConsoleGameRegion;

    NTSYSAPI
    EXPORTNUM(13)
    DWORD
    NTAPI
    ExCreateThread(
        IN        PHANDLE pHandle,
        IN        DWORD dwStackSize,
        IN        LPDWORD lpThreadId,
        IN        PVOID apiThreadStartup,
        IN        LPTHREAD_START_ROUTINE lpStartAddress,
        IN        LPVOID lpParameter,
        IN        DWORD dwCreationFlagsMod
    );

    NTSYSAPI
    EXPORTNUM(15)
    VOID
    NTAPI
    ExFreePool(
        IN PVOID  pPool
    );

	NTSTATUS ObTranslateSymbolicLink(IN PVOID, OUT PANSI_STRING);

	NTSTATUS NtSetSystemTime(IN PLARGE_INTEGER SystemTime, OUT PLARGE_INTEGER PreviousTime OPTIONAL);

	NTSTATUS NtCreateFile(HANDLE* FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, 
		ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions);

	NTSTATUS NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions); 

	NTSTATUS NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, PANSI_STRING FileMask, DWORD Unkn);

	NTSTATUS NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, 
		PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset);
	NTSTATUS NtWriteFile(HANDLE FileHandle, IN HANDLE Event OPTIONAL, IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock, IN PVOID Buffer, IN ULONG Length, IN PLARGE_INTEGER ByteOffset OPTIONAL);

	NTSTATUS NtOpenDirectoryObject(PHANDLE DirectoryHandle, POBJECT_ATTRIBUTES ObjectAttributes);

	NTSTATUS NtQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, 
		BOOLEAN ReturnSingleEntry, PULONG Context, PULONG ReturnLength);

	NTSTATUS NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
		PVOID FileInformation, ULONG Length, DWORD FileInformationClass);

	NTSTATUS NtClose(HANDLE Handle);

    // tested on 9199 rebooter/freeboot
    // 0 hard poweroff (used by hotplug HDD) HalpPowerDownSystemNow
    // 1 hard reset (video error) HalpRebootSystem
    // 2 hard reset (used for dumpwritedump/frozen processor) HalpRebootSystem
    // 3 hard reset HalpRebootSystem
    // 4 power off (hard) HalpRebootSystem
    // 5 power off (nice) HalpPowerDownSystem
    // 6 E79 (lost settings) HalpRebootQuiesceSystem
    // 7 frozen console HalpRequestPowerDownDpc
    NTSYSAPI
    EXPORTNUM(40)
    VOID
    NTAPI
    HalReturnToFirmware(
        IN        FIRMWARE_REENTRY dwPowerDownMode
    );

    NTSYSAPI
    UCHAR
    EXPORTNUM(102)
    NTAPI
    KeGetCurrentProcessType(
        VOID
    );

    NTSYSAPI
    EXPORTNUM(224)
    NTSTATUS
    NTAPI
        NtOpenSymbolicLinkObject(
        OUT        PHANDLE LinkHandle,
        IN        POBJECT_ATTRIBUTES ObjectAttributes
    );

    NTSYSAPI
    EXPORTNUM(231)
    NTSTATUS
    NTAPI
    NtQueryFullAttributesFile(
        IN        POBJECT_ATTRIBUTES ObjectAttributes,
        OUT        PFILE_NETWORK_OPEN_INFORMATION Attributes
    );

    NTSYSAPI
    EXPORTNUM(236)
    NTSTATUS
    NTAPI
    NtQuerySymbolicLinkObject(
        IN        HANDLE LinkHandle,
        IN OUT    PSTRING LinkTarget,
        OUT        PULONG ReturnedLength OPTIONAL
    );

    NTSYSAPI
    EXPORTNUM(259)
    HRESULT
    NTAPI
    ObCreateSymbolicLink(
        IN        PSTRING SymbolicLinkName,
        IN        PSTRING DeviceName
    );

    NTSYSAPI
    EXPORTNUM(260)
    HRESULT
    NTAPI
    ObDeleteSymbolicLink(
        IN        PSTRING SymbolicLinkName
    );

    NTSYSAPI
    EXPORTNUM(299)
    PVOID
    NTAPI
    RtlImageXexHeaderField(
        IN        PVOID XexHeaderBase,
        IN        DWORD ImageField
    );

    NTSYSAPI
    EXPORTNUM(300)
    VOID
    NTAPI
    RtlInitAnsiString(
        IN OUT    PANSI_STRING DestinationString,
        IN        PCSZ  SourceString
    );

    EXPORTNUM(342)
    extern PXBOX_HARDWARE_INFO XboxHardwareInfo;

    EXPORTNUM(344)
    extern PXBOX_KRNL_VERSION XboxKrnlVersion;

    NTSYSAPI
    EXPORTNUM(404)
    BOOL
    NTAPI
    XexCheckExecutablePrivilege(
        IN        DWORD priviledge
    );

    // ie XexGetModuleHandle("xam.xex", &hand), returns 0 on success
    NTSYSAPI
    EXPORTNUM(405)
    NTSTATUS
    NTAPI
    XexGetModuleHandle(
        IN        char* moduleName,
        IN OUT    PHANDLE Handle
    );

    // ie XexGetProcedureAddress(hand ,0x50, &addr) returns 0 on success
    NTSYSAPI
    EXPORTNUM(407)
    DWORD
    NTAPI
    XexGetProcedureAddress(
        IN        HANDLE Handle,
        IN        DWORD dwOrdinal,
        IN        DWORD* Address
    );

    NTSYSAPI
    EXPORTNUM(408)
    DWORD
    NTAPI
    XexLoadExecutable(
        IN        PCHAR xexName,
        IN OUT    PHANDLE handle,
        IN        DWORD typeInfo,
        IN        DWORD ver
    );

    NTSYSAPI
    EXPORTNUM(409)
    DWORD
    NTAPI
    XexLoadImage(
        IN        LPCSTR xexName,
        IN        DWORD typeInfo,
        IN        DWORD ver,
        IN OUT    PHANDLE modHandle
    );

    NTSYSAPI
    EXPORTNUM(486)
    NTSTATUS
    NTAPI
    XInputdReadState(
        IN        PDWORD DeviceContext,
        OUT        PDWORD pdwPacketNumber,
        OUT        PXINPUT_GAMEPAD pInputData
    );

    NTSYSAPI
    EXPORTNUM(611)
    void
    NTAPI
    AniTerminateAnimation(
        VOID
    );

	VOID    __cdecl        XapiThreadStartup(
        VOID    (__cdecl *StartRoutine)(VOID *), 
        VOID    *StartContext
        );


#ifdef __cplusplus
}
#endif

#endif    //_KERNEL_DEFINES_H
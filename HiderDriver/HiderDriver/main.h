#include <ntddk.h>
#include <wdm.h>
#include <ntimage.h>
#include <windef.h>

#define DEVICE_NAME L"\\\\.\\MyDevice"

#define IOCTL_CREATE_DIRECTORY \
		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_HIDE_PROCESS \
		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

PVOID GetKernelBase();

//PVOID FindFunction(
//    _In_ PVOID KernelBaseAddress,
//    _In_ PCSTR TargetFunctionName
//);
//
//NTSTATUS SetFolderPermissions(
//    _In_ UNICODE_STRING ImagePath,
//    _In_ ACCESS_MASK CurrentAccessMask
//);
//
//NTSTATUS GetWindowsVersion(
//    _In_ ULONG* MajorVersion,
//    _In_ ULONG* MinorVersion,
//    _In_ ULONG* BuildNumber
//);
//
//ULONG GetActiveProcessLinkOffset();
//
//NTSTATUS HideProcess(
//    _In_ HANDLE ProcessID
//);
//
//NTSTATUS CreateHiddenFile();
//
//NTSTATUS DriverEntry(
//    _In_ PDRIVER_OBJECT DriverObject,
//    _In_ PUNICODE_STRING RegistryPath
//);


/*

    All Structs From https://ntdoc.m417z.com/

*/


typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;                 // Not used
    PVOID MappedBase;               // Not used
    PVOID ImageBase;                // Base address of the module
    ULONG ImageSize;                // Size of the module
    ULONG Flags;                    // Flags
    USHORT LoadOrderIndex;          // Load order index
    USHORT InitOrderIndex;          // Init order index
    USHORT LoadCount;               // Load count
    USHORT OffsetToFileName;        // Offset to the module name
    UCHAR FullPathName[256];        // Full path to the module
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;          // Number of modules
    RTL_PROCESS_MODULE_INFORMATION Modules[1]; // Array of module information
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef NTSTATUS(NTAPI* fp_ZwQuerySystemInformation)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fpRtlAddAccessDeniedAceEx)(
    _Inout_ PACL Acl,
    _In_ ULONG AceRevision,
    _In_ ULONG AceFlags,
    _In_ ACCESS_MASK AccessMask,
    _In_ PSID Sid
    );
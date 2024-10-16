#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#define IOCTL_GET_PROCESSNAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " << argv[0] << " <process_name>" << endl;
        return 1;
    }

    string procName = argv[1];

    HANDLE hDevice = CreateFile(L"\\\\.\\HideProcess", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        cout << "Failed to open device, error: " << GetLastError() << endl;
        return 1;
    }

    DWORD bytesReturned;
    // Asegúrate de enviar correctamente el buffer de entrada
    BOOL result = DeviceIoControl(hDevice, IOCTL_GET_PROCESSNAME, (LPVOID)procName.c_str(), (DWORD)(procName.length() + 1), NULL, 0, &bytesReturned, NULL);

    if (result)
    {
        cout << "Process name sent successfully: " << procName << endl;
    }
    else
    {
        cout << "Failed to send process name. Error: " << GetLastError() << endl;
    }

    CloseHandle(hDevice);
    return 0;
}

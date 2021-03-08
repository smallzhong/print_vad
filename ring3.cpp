#include "StdAfx.h"
#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <winioctl.h>

using namespace std;

#define DRIVER_NAME L"Project1"
#define DRIVER_PATH L"Project1.sys"
#define DRIVER_LINK L"\\\\.\\HbgDevLnk"

#define OPER_PRINT_VAD \
CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)


int main()
{
	DWORD dwRetBytes = 0;
	HANDLE hDevice = CreateFileW(DRIVER_LINK, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	printf("0x%x\n", hDevice);

	if (DeviceIoControl(hDevice, OPER_PRINT_VAD, NULL, 0, NULL, 0, &dwRetBytes, NULL) == 0)
	{
		printf("error = %d\n", GetLastError());
		CloseHandle(hDevice);
		printf("与驱动通信出错");
	}
	CloseHandle(hDevice);
	
	getchar();
	
	return 0;
}
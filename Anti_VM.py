from winappdbg import *
from winappdbg.win32.defines import *
#from winappdbg.win32.ntdll import *

import time
import Extract
import Anti_VM_Check
import Anti_Debugging_Check


class Anti_VM_Start(EventHandler):
    apiHooks = {

        'kernel32.dll': [
            ('GetSystemInfo', 1),  # Anti VM
            ('GlobalMemoryStatusEx', 1),  # Anti VM
            ('DeviceIoControl', 8),  # Anti VM (HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
            ('FindFirstFileW', 2)  # Anti VM (LPCWSTR, LPWIN32_FIND_DATAW)
        ],


        'advapi32.dll': [
            ('RegOpenKeyExW', 5)  # Anti VM (HKEY, LPCWSTR, DWORD, REGSAM, PHKEY)
        ],

        'setupapi.dll': [
            ('SetupDiGetDeviceRegistryPropertyW', 7) # Anti VM (HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD)
        ]
    }
    def __init__(self, param1):
        super(Anti_VM_Start, self).__init__()
        self.bypass = param1    # Bypass Mode Value

        self.AntiVM = Anti_VM_Check.AntiVM_Check()

    def create_process(self, event):
        process, pid, tid, module, thread, registers = Extract.get_all(event)

    def load_dll(self, event):
        process, pid, tid, module, thread, registers = Extract.get_all(event)

    def pre_GetSystemInfo(self, event, ra, system_info_structure):

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.AntiVM.GetSystemInfo(event, system_info_structure, return_address, self.bypass)

    def pre_GlobalMemoryStatusEx(self, event, ra, memory_status_structure):

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.AntiVM.GlobalMemoryStatus(event, memory_status_structure, return_address, self.bypass)

    def pre_DeviceIoControl(self, event, ra, hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer,
                            nOutBufferSize, lpBytesReturned, lpOverlapped):
        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.AntiVM.DeviceIoControl(event, dwIoControlCode, lpOutBuffer, return_address, self.bypass)

    def pre_FindFirstFileW(self, event, ra, lpfilename, lpFindFileData):
        self.AntiVM.FindFirstFileW_Check(event, lpfilename, self.bypass)

    def pre_RegOpenKeyExW(self, event, ra, hkey, lpsubkey, uloptions, samdesired, phkResult):
        self.AntiVM.RegOpenKeyExW_Check(event, hkey, lpsubkey, self.bypass)

    def pre_SetupDiGetDeviceRegistryPropertyW(self, event, ra, de_info_set, de_info_data, pro, pro_reg, pro_buf,
                                              pro_size, requ_size):
        self.AntiVM.SetupDiGetDeviceRegistryPropertyW(event, pro_buf, self.bypass)




#-*- coding:utf-8 -*-
from winappdbg import *
from winappdbg.win32.defines import *

import AntiDebugging
import AntiVM
#import AntiVM
import Extract

class Debugging_PE(EventHandler):

    AntiDebugging_Checker = AntiDebugging.AntiDebugging_Check()
    AntiVM_Checker = AntiVM.AntiVM_Check()

    apiHooks = {

        'kernel32.dll' : [
            ('IsDebuggerPresent', 0), # Anti Debugging
            ('CheckRemoteDebuggerPresent', 2), # Anti Debugging
            ('FindWindow', 2), # Anti Debugging
            #('OutputDebugStringA', 1),
            ('GetSystemInfo', 1), # Anti VM
            ('GlobalMemoryStatusEx', 1), # Anti VM
            ('DeviceIoControl', 8), # Anti VM (HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)
            ('FindFirstFileW', 2) # Anti VM (LPCWSTR, LPWIN32_FIND_DATAW)
        ],

        'ntdll.dll' : [
            ('NtQueryInformationProcess', 5), # Anti Debugging (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)
            ('NtSetInformationThread', 4), # Anti Debugging (HANDLE, THREADINFOCLASS, PVOID, ULONG)
            ('NtQuerySystemInformation', 4), # Anti Debugging (SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG)
            ('NtClose', 1) # Anti Debugging (HANDLE)
        ],

        'advapi32.dll' : [
            ('RegOpenKeyExW', 5)  # Anti VM (HKEY, LPCWSTR, DWORD, REGSAM, PHKEY)
        ],

        'setupapi.dll' : [
            ('SetupDiGetDeviceRegistryPropertyW', 7) # Anti VM (HDEVINFO, PSP_DEVINFO_DATA, DWORD, PDWORD, PBYTE, DWORD, PDWORD)
        ]
    }

    # test
    '''
    def ms_vc_exception(self, event):
        code = event.get_exception_code()
        name = event.get_exception_name()

        print (code)
        print (name)

    def exception(self, event):
        thread = event.get_thread()

        print ("AETAEWTEAWTEAWTAEWTAEWTW")

        exception_name = event.get_exception_name()
        exception_description = event.get_exception_description()

        exception_code = event.get_exception_code()
        exception_address = event.get_exception_address()

        print (exception_name)

        if exception_name == "EXCEPTION_INVALID_HANDLE":
            Extract.Printer_Check("INVALID_HANDLE Exception Check, NtClose or CloseHandle Use") # NtClose or CloseHandle
    '''

    def create_process(self, event):
        process, pid, tid, module, thread, registers = Extract.get_all(event)

        #phandle = event.get_handle()

        #print (phandle)

        peb_address = process.get_peb_address()

        bits = Extract.check_bit(event)

        BeingDebugged_Value = process.read_char(peb_address + 0x2) # PEB!BeingDebugged

        self.AntiDebugging_Checker.peb_beingdebugged(event, BeingDebugged_Value) # PEB!BeingDebugged Check

        # Heap Flag -> Need to check HeapGrowable
        if bits == 32:
            NtGlobalFlag = process.read_char(peb_address + 0x68) # PEB!NtGlobalFlag
            HeapFlag = process.read_dword(peb_address + 0x18) # PEB!HeapFlag
            Heap_offset = 0x44

            self.AntiDebugging_Checker.peb_NtGlobalFlag(event, NtGlobalFlag, peb_address + 0x68)
            self.AntiDebugging_Checker.peb_HeapFlag(event, HeapFlag, Heap_offset) # heap flag & heap base

        # Heap Flag -> Need to check HeapGrowable
        else:
            NtGlobalFlag = process.read_dword(peb_address + 0xbc) # PEB!NtGlobalFlag
            HeapFlag = process.read_qword(peb_address + 0x30) # PEB!HeapFlag
            Heap_offset = 0x74

            self.AntiDebugging_Checker.peb_NtGlobalFlag(event, NtGlobalFlag, peb_address + 0xbc)
            self.AntiDebugging_Checker.peb_HeapFlag(event, HeapFlag, Heap_offset) # heap flag & heap base

    def load_dll(self, event):
        process, pid, tid, module, thread, registers = Extract.get_all(event)

    def post_IsDebuggerPresent(self, event, retval): # IsDebuggerPresent

        IsDebuggerPresent_Check = self.AntiDebugging_Checker.IsDebuggerPresent(event, retval) # Check

        if IsDebuggerPresent_Check: # Bypass
            self.AntiDebugging_Checker.IsDebuggerPresent_Bypass(event)

    def pre_CheckRemoteDebuggerPresent(self, event, ra, handle, pbool):

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.AntiDebugging_Checker.CheckRemoteDebuggerPresent(event, pbool, return_address) # Check & Bypass


    def pre_NtQueryInformationProcess(self, event, ra, handle, processinfoclass, pvoid, ulong, pulong): # ProcessDebugPort, ProcessObjectHandle

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.AntiDebugging_Checker.NtQueryInformationProcess_Flags(event, processinfoclass, pvoid, return_address)

    def pre_GetSystemInfo(self, event, ra, system_info_structure):

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.AntiVM_Checker.GetSystemInfo_Data(event, system_info_structure, return_address)

    def pre_GlobalMemoryStatusEx(self, event, ra, memory_status_structure):

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.AntiVM_Checker.GlobalMemoryStatus_Data(event, memory_status_structure, return_address)

    def pre_DeviceIoControl(self, event, ra, hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped):

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.AntiVM_Checker.DeviceIoControl_Data(event, dwIoControlCode, lpOutBuffer, return_address)

    def pre_FindFirstFileW(self, event, ra, lpfilename, lpFindFileData):

        self.AntiVM_Checker.FindFirstFileW_Check_Bypass(event, lpfilename)

    def pre_RegOpenKeyExW(self, event, ra, hkey, lpsubkey, uloptions, samdesired, phkResult):

        self.AntiVM_Checker.RegOpenKeyExW_Check_Bypass(event, hkey, lpsubkey)

    def pre_SetupDiGetDeviceRegistryPropertyW(self, event, ra, de_info_set, de_info_data, pro, pro_reg, pro_buf, pro_size, requ_size):

        self.AntiVM_Checker.SetupDiGetDeviceRegistryPropertyW_Check_Bypass(event, pro_buf)

    def pre_NtSetInformationThread(self, event, ra, thradhandle, threadinformationclass, threadinformation, threadinformationlen):

        self.AntiDebugging_Checker.NtSetInformationThread_Check_and_Bypass(event, threadinformationclass)

    def pre_NtQuerySystemInformation(self, event, ra, systeminformatinoclass, systeminformation, syusteminformationlength, returnlength):

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.AntiDebugging_Checker.NtQuerySystemInformation_Data(event, systeminformatinoclass, systeminformation, return_address)

    def pre_NtClose(self, event, ra, handle):

        self.AntiDebugging_Checker.NtClose_Check_and_Bypass(event, handle)

def Debugging_Start(process):

    with Debug(Debugging_PE(), bKillOnExit=True) as debug:
        debug.execv(process)

        debug.loop()

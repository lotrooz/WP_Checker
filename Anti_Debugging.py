from winappdbg import *
from winappdbg.win32.defines import *
#from winappdbg.win32.ntdll import *

import time
import Extract
import Anti_Debugging_Check
class Anti_Debugging_Start(EventHandler):

    apiHooks = {
        'kernel32.dll': [
            ('IsDebuggerPresent', 0),
            ('CheckRemoteDebuggerPresent', 2),  # Anti Debugging
        ],

        'ntdll.dll': [
            ('NtQueryInformationProcess', 5),  # Anti Debugging (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)
            ('NtQuerySystemInformation', 4),  # Anti Debugging (SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG)
            ('NtSetInformationThread', 4),  # Anti Debugging (HANDLE, THREADINFOCLASS, PVOID, ULONG)
            ('NtClose', 1),  # Anti Debugging (HANDLE)
            ('NtOpenProcess', 4), # Anti Debugging (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)
            ('LdrLoadDll', 4) # Anti Debugging (PWCHAR, ULONG, PUNICODE_STRING, PHANDLE)
        ]
    }

    def __init__(self, param1):
        super(Anti_Debugging_Start, self).__init__()
        self.bypass = param1    # Bypass Mode Value

        self.Anti = Anti_Debugging_Check.AntiDebugging_Check()

    def create_process(self, event):
        process, pid, tid, module, thread, registers = Extract.get_all(event)

        peb_address = process.get_peb_address()

        peb = process.get_peb()

        bits = Extract.check_bit(event)

        self.csr_pid = win32.CsrGetProcessId() # NtOpenProcess
        self.process_name = process.get_filename() # LdrLoadDll

        # [+] PEB!BeingDebugged
        BeingDebugged_Value = process.read_char(peb_address + 0x2)

        self.Anti.peb_beingdebugged(event, BeingDebugged_Value, self.bypass)
        # [+] PEB!BeingDebugged Finish

        Major_Version = win32.GetVersionExA().dwMajorVersion # Windows Version

        if bits == 32:
            # [+] PEB!NtGlobalFlag_32bit
            NtGlobalFlag = process.read_char(peb_address + 0x68) # PEB!NtGlobalFlag, Fix

            self.Anti.peb_NtGlobalFlag(event, NtGlobalFlag, peb_address + 0x68, self.bypass)
            # [+] PEB!NtGlobalFlag_32bit Finish

            ''' Fix it
            process_heap = process.read_dword(peb_address + 0x18)  # PEB!HeapFlag

            if (Major_Version < 6):
                heap_flag_offset = 0xC
                heap_force_offset = 0x10

            else:
                heap_flag_offset = 0x40
                heap_force_offset = 0x44

            heap_flag = process.read_dword(process_heap + heap_flag_offset)
            heap_force = process.read_dword(process_heap + heap_force_offset)

            self.Anti.peb_HeapFlag(event, heap_flag, heap_force)  # heap flag & heap base
            '''

        else:
            # [+] PEB!NtGlobalFlag_64bit
            NtGlobalFlag = process.read_dword(peb_address + 0xbc) # PEB!NtGlobalFlag, Fix

            self.Anti.peb_NtGlobalFlag(event, NtGlobalFlag, peb_address + 0xbc, self.bypass)
            # [+] PEB!NtGlobalFlag_64bit Finish

            #time.sleep(10)

            ''' Fix it
            #process_heap = process.read_qword(peb_address + 0x30)  # PEB!HeapFlag , Fix

            if (Major_Version < 6):
                heap_flag_offset = 0x14
                heap_force_offset = 0x18

            else:
                heap_flag_offset = 0x70
                heap_force_offset = 0x74


            #print (heap_flag_offset)
            #print (hex(peb_address))
            #print (hex(peb_address+0x30))
            #print (hex(process_heap))



            #heap_flag = process.read_dword(process_heap + heap_flag_offset)
            #heap_force = process.read_dword(process_heap + heap_force_offset)

            #self.Anti.peb_HeapFlag(event, heap_flag, heap_force)  # heap flag & heap base
            '''


    def load_dll(self, event):
        process, pid, tid, module, thread, registers = Extract.get_all(event)

        if module.match_name("ntdll.dll"):
            # Get the process ID.
            peb_address = process.get_peb_address()

            peb = process.get_peb()





    # [+] IsDebuggerPresent
    def post_IsDebuggerPresent(self, event, retval):  # IsDebuggerPresent

        IsDebuggerPresent_Check = self.Anti.IsDebuggerPresent(event, retval)  # Check

        if (IsDebuggerPresent_Check and self.bypass):  # Bypass
            self.Anti.IsDebuggerPresent_Bypass(event)

    # [+] CheckRemoteDebuggerPresent
    def pre_CheckRemoteDebuggerPresent(self, event, ra, handle, pbool):

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.Anti.CheckRemoteDebuggerPresent(event, pbool, return_address, self.bypass) # Check & Bypass

    # [+] NtQueryInformationProcess (Debug Port, Object Handle, Debug Flags)
    def pre_NtQueryInformationProcess(self, event, ra, handle, systeminformatinoclass, systeminformation, info_len,re_len):
        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.Anti.NtQueryInformationProcess_Flags(event, systeminformatinoclass, systeminformation, return_address, self.bypass)

    # [+] NtSetInformationThread
    def pre_NtSetInformationThread(self, event, ra, thradhandle, threadinformationclass, threadinformation, threadinformationlen):

        self.Anti.NtSetInformationThread_Check(event, threadinformationclass, self.bypass)

    # [+] NtQuerySystemInformation
    def pre_NtQuerySystemInformation(self, event, ra, systeminformatinoclass, systeminformation, syusteminformationlength, returnlength):

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.Anti.NtQuerySystemInformation_Flags(event, systeminformatinoclass, systeminformation, return_address, self.bypass)

    # [+] NtClose
    def pre_NtClose(self, event, ra, handle):

        self.Anti.NtClose_Check(event, handle, self.bypass)

    # [+] NtOpenProcess
    def pre_NtOpenProcess(self, event, ra, phandle, access, attributes, pclinet_id):

        process = event.get_process()

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        if process.read_dword(pclinet_id) == self.csr_pid:  # csrss.exe Process Open Check
            self.Anti.NtOpenProcess_Flags(event, return_address, self.bypass)

    # [+] LdrLoadDll
    def pre_LdrLoadDll(self, event, ra, path_file, flags, module_file, module_handle):

        process = event.get_process()
        # path_file int ... ??
        #print (hex(module_file))
        #print (process.read_string(module_file, 0x20)) # ???

        self.Anti.LdrLoadDll_Check(event, self.process_name, path_file, self.bypass)




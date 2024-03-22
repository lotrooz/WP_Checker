from winappdbg import *
from winappdbg.win32.defines import *

import Extract
import Anti_Debugging_Check
class Anti_Debugging_Start(EventHandler):

    apiHooks = {
        'kernel32.dll': [
            ('IsDebuggerPresent', 0),
            ('CheckRemoteDebuggerPresent', 2),  # Anti Debugging
        ],

        'ntdll.dll': [
            ('NtQuerySystemInformation', 4),  # Anti Debugging (SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG)
        ]
    }

    def __init__(self, param1):
        super(Anti_Debugging_Start, self).__init__()
        self.bypass = param1    # Bypass Mode Value

        self.Anti = Anti_Debugging_Check.AntiDebugging_Check()

    def create_process(self, event):
        process, pid, tid, module, thread, registers = Extract.get_all(event)

        peb_address = process.get_peb_address()

        bits = Extract.check_bit(event)

        # [+] # PEB!BeingDebugged
        BeingDebugged_Value = process.read_char(peb_address + 0x2)

        self.Anti.peb_beingdebugged(event, BeingDebugged_Value, self.bypass)
        # [+] # # PEB!BeingDebugged Finish

        if bits == 32:
            NtGlobalFlag = process.read_char(peb_address + 0x68) # PEB!NtGlobalFlag, Fix

            HeapFlag = process.read_dword(peb_address + 0x18)  # PEB!HeapFlag
            Heap_offset = 0x44

            self.Anti.peb_NtGlobalFlag(event, NtGlobalFlag, peb_address + 0x68)
            self.Anti.peb_HeapFlag(event, HeapFlag, Heap_offset)  # heap flag & heap base

        else:
            NtGlobalFlag = process.read_dword(peb_address + 0xbc) # PEB!NtGlobalFlag, Fix

            HeapFlag = process.read_qword(peb_address + 0x30)  # PEB!HeapFlag , Fix
            Heap_offset = 0x74

            self.Anti.peb_NtGlobalFlag(event, NtGlobalFlag, peb_address + 0xbc)
            self.Anti.peb_HeapFlag(event, HeapFlag, Heap_offset)  # heap flag & heap base


        print (self.bypass)


        print (bits)


    def load_dll(self, event):
        process, pid, tid, module, thread, registers = Extract.get_all(event)

    def post_IsDebuggerPresent(self, event, retval):  # IsDebuggerPresent

        IsDebuggerPresent_Check = self.Anti.IsDebuggerPresent(event, retval)  # Check

        if (IsDebuggerPresent_Check and self.bypass):  # Bypass
            self.Anti.IsDebuggerPresent_Bypass(event)

    def pre_CheckRemoteDebuggerPresent(self, event, ra, handle, pbool):

        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.Anti.CheckRemoteDebuggerPresent(event, pbool, return_address, self.bypass) # Check & Bypass

    def pre_NtQuerySystemInformation(self, event, ra, systeminformatinoclass, systeminformation, syusteminformationlength, returnlength):
        bits = Extract.check_bit(event)

        return_address = Extract.check_csp(event, bits)

        self.Anti.NtQuerySystemInformation_Data(event, systeminformatinoclass, systeminformation, return_address)




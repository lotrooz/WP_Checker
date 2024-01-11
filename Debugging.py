#-*- coding:utf-8 -*-
from winappdbg import *
from winappdbg.win32.defines import *

import AntiDebugging
#import AntiVM
import Extract

class Debugging_PE(EventHandler):

    AntiDebugging_Checker = AntiDebugging.AntiDebugging_Check()

    apiHooks = {

        'kernel32.dll' : [
            ('IsDebuggerPresent', 0),
            ('CheckRemoteDebuggerPresent', 2),
            ('FindWindow', 2)
            #('OutputDebugStringA', 1),
        ],

        'ntdll.dll' : [
            ('NtQueryInformationProcess', 5) # (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)
        ]

    }

    def create_process(self, event):
        process, pid, tid, module, thread, registers = Extract.get_all(event)

        peb_address = process.get_peb_address()

        bits = Extract.check_bit(event)

        BeingDebugged_Value = process.read_char(peb_address + 0x2) # PEB!BeingDebugged

        self.AntiDebugging_Checker.peb_beingdebugged(event, BeingDebugged_Value) # PEB!BeingDebugged Check

        if bits == 32:
            NtGlobalFlag = process.read_char(peb_address + 0x68) # PEB!NtGlobalFlag

            self.AntiDebugging_Checker.peb_NtGlobalFlag(event, NtGlobalFlag, peb_address + 0x68)


        else:
            NtGlobalFlag = process.read_dword(peb_address + 0xbc) # PEB!NtGlobalFlag

            self.AntiDebugging_Checker.peb_NtGlobalFlag(event, NtGlobalFlag, peb_address + 0xbc)



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





def Debugging_Start(process):

    with Debug(Debugging_PE(), bKillOnExit=True) as debug:
        debug.execv(process)

        debug.loop()

#-*- coding:utf-8 -*-
from winappdbg import *

import time
import Extract
import Anti_Debugging
import traceback

class AntiDebugging_Check(object):

    def peb_beingdebugged(self, event, peb_beingdebugged, bypass):
        if (peb_beingdebugged == 1): # Check
            process = event.get_process()

            peb_address = process.get_peb_address()

            Extract.Printer_Check("PEB!BeingDebugged")

            if (bypass):
                process.write_char(peb_address + 0x2, 0)  # Bypass

                Extract.Printer_Bypass("PEB!BeingDebugged")

    def peb_NtGlobalFlag(self, event, peb_ntglobalflag, ntglobalflag_address, bypass):

        if (peb_ntglobalflag == 0x70): # Check
            process = event.get_process()

            Extract.Printer_Check("PEB!NtGlobalFlag")

            if (bypass):
                process.write_char(ntglobalflag_address, 0) # Bypass

                Extract.Printer_Bypass("PEB!NtGlobalFlag")

    # Heap Flag -> Need to check HeapGrowable 
    def peb_HeapFlag(self, event, peb_heapflag, offset):
        process = event.get_process()




    def IsDebuggerPresent(self, event, return_value):

        if return_value == 1:
            Extract.Printer_Check("IsDebuggerPresent")
            return True

        else:
            Extract.Printer_NotCheck("IsDebuggerPresent")
            return False

    def IsDebuggerPresent_Bypass(self, event):

        thread = event.get_thread()

        bits = Extract.check_bit(event)

        if bits == 32: # 32bit bypass
            thread.set_register("Eax", 0)

            if Extract.registers(event,"Eax") == 0:
                Extract.Printer_Bypass("IsDebuggerPresent")

            else:
                Extract.Printer_NotBypass("IsDebuggerPresent")

        else: # 64bit bypass
            thread.set_register("Rax", 0)

            if Extract.registers(event, "Rax") == 0:
                Extract.Printer_Bypass("IsDebuggerPresent")

            else:
                Extract.Printer_NotBypass("IsDebuggerPresent")

    def CheckRemoteDebuggerPresent(self, event, second, return_address, bypass):

        pid = event.get_pid()

        self.remote_second_address = second
        self.remote_RemoteDebuggerPresent_return_address = return_address
        self.remote_bypass = bypass

        event.debug.break_at(pid, self.remote_RemoteDebuggerPresent_return_address, self.CheckRemoteDebuggerPresent_Check) # return addreses breakpoint set

    def CheckRemoteDebuggerPresent_Check(self, event):

        process = event.get_process()

        CheckRemoteDebuggerPresent_Check = process.peek_int(self.remote_second_address)

        if CheckRemoteDebuggerPresent_Check == 1: # Check
            Extract.Printer_Check("CheckRemoteDebuggerPresent")

            if self.remote_bypass:
                process.write_int(self.remote_second_address, 0) # Bypass

                Extract.Printer_Bypass("CheckRemoteDebuggerPresent")



    def NtQueryInformationProcess_Flags(self, event, flags, buffer, return_address, bypass):

        pid = event.get_pid()

        self.NtQuery_flags = flags
        self.NtQuery_buffer = buffer
        self.NtQuery_return_address = return_address
        self.NtQuery_bypass = bypass

        CheckFlags_Value = self.NtQuery_flags

        if (CheckFlags_Value == 0x7):
            Extract.Printer_Check_Logic("NtQueryInformationProcess DebugPort")
            event.debug.break_at(pid, self.NtQuery_return_address, self.NtQueryInformationProcess_Check)

        elif (CheckFlags_Value == 0x1E):
            Extract.Printer_Check_Logic("NtQueryInformationProcess ObjectHandle")
            event.debug.break_at(pid, self.NtQuery_return_address, self.NtQueryInformationProcess_Check)

        elif (CheckFlags_Value == 0x1F):
            Extract.Printer_Check_Logic("NtQueryInformationProcess Flags")
            event.debug.break_at(pid, self.NtQuery_return_address, self.NtQueryInformationProcess_Check)


        # # return address breakpoint set

    def NtQueryInformationProcess_Check(self, event):

        process = event.get_process()
        pid = event.get_pid()
        bits = Extract.check_bit(event)

        if (self.NtQuery_flags == 0x7):     # Check Debug Port
            if bits == 32:
                CheckBuffer_Value = process.read_dword(self.NtQuery_buffer)

                if CheckBuffer_Value == 0xffffffff:
                    Extract.Printer_Check("NtQueryInformationProcess DebugPort")

                    if self.NtQuery_bypass:
                        process.write_dword(self.NtQuery_buffer, 0)
                        Extract.Printer_Bypass("NtQueryInformationProcess DebugPort")

            else:
                CheckBuffer_Value = process.read_qword(self.NtQuery_buffer)

                if CheckBuffer_Value == 0xffffffffffffffff:
                    Extract.Printer_Check("NtQueryInformationProcess DebugPort")

                    if self.NtQuery_bypass:
                        process.write_dword(self.NtQuery_buffer, 0)

                        Extract.Printer_Bypass("NtQueryInformationProcess DebugPort")

        if (self.NtQuery_flags == 0x1E):        # Check Object Handle
            if bits == 32:
                CheckBuffer_Value = process.read_dword(self.NtQuery_buffer)

                if CheckBuffer_Value != 0:  # Debugging Check 32
                    Extract.Printer_Check("NtQueryInformationProcess ObjectHandle")

                    if self.NtQuery_bypass:
                        process.write_dword(self.NtQuery_buffer, 0) # Bypass

                        Extract.Printer_Bypass("NtQueryInformationProcess ObjectHandle")

            else:
                CheckBuffer_Value = process.read_qword(self.NtQuery_buffer)

                if CheckBuffer_Value != 0:  # Debugging Check 64
                    Extract.Printer_Check("NtQueryInformationProcess ObjectHandle")

                    if self.NtQuery_bypass:
                        process.write_qword(self.NtQuery_buffer, 0)  # Bypass

                        Extract.Printer_Bypass("NtQueryInformationProcess ObjectHandle")

        if (self.NtQuery_flags == 0x1F):  # Check Process Debug Flags
            CheckBuffer_Value = process.read_dword(self.NtQuery_buffer)

            if CheckBuffer_Value == 0:  # Debugging Check
                Extract.Printer_Check("NtQueryInformationProcess Flags")

                if self.NtQuery_bypass:
                    process.write_dword(self.NtQuery_buffer, 1)  # Bypass

                    Extract.Printer_Bypass("NtQueryInformationProcess Flags")

        event.debug.dont_break_at(pid, self.NtQuery_return_address)


    def NtSetInformationThread_Check(self, event, threadinfo_class, bypass):

        if threadinfo_class == 0x11:

            Extract.Printer_Check("NtSetInformationThread")

            process = event.get_process()
            thread = event.get_thread()
            registers = thread.get_context()
            bits = Extract.check_bit(event)

            if bypass:
                if bits == 32:
                    check_value = registers['Esp'] + 0x4 # Bypass
                    process.write_dword(check_value, 0)

                else:
                    thread.set_register('Rdx', 0) # Bypass Check.. Rcx ??

                Extract.Printer_Bypass("NtSetInformationThread")



    def NtQuerySystemInformation_Flags(self, event, systeminformatinoclass, systeminformation, return_address, bypass):
        pid = event.get_pid()

        self.NtSystem_class = systeminformatinoclass
        self.NtSystem_info = systeminformation
        self.NtSystem_return_address = return_address
        self.NtSystem_bypass = bypass

        if (self.NtSystem_class == 0x23):
            Extract.Printer_Check_Logic("NtQuerySystemInformation_Flags")
            event.debug.break_at(pid, self.NtSystem_return_address, self.NtQuerySystemInformation_Check)

    def NtQuerySystemInformation_Check(self, event):

        process = event.get_process()
        check_system_info = self.NtSystem_info

        DebuggerEnabled = process.read_char(check_system_info)    # al , Debugging -> 1
        DebuggerNotPresent = process.read_char(check_system_info + 0x1)   #ah , Debugging -> 0

        if (DebuggerEnabled or not DebuggerNotPresent):
            Extract.Printer_Check("NtQuerySystemInformation")

            if self.NtSystem_bypass:    # bypass
                process.write_char(check_system_info, 0) # DebuggerEnabled -> 0
                process.write_char(check_system_info, 1) # DebuggerNotPresent -> 1

                Extract.Printer_Bypass("NtQuerySystemInformation")

    def NtClose_Check(self, event, handle, bypass):

        process = event.get_process()
        thread = event.get_thread()
        registers = thread.get_context()
        bits = Extract.check_bit(event)

        try:
            win32.GetHandleInformation(handle)

        except Exception as e:
            if isinstance(e, WindowsError):
                if e.winerror == 6:         # invalid handle

                    Extract.Printer_Check("NtClose")

                    if bypass:
                        if bits == 32:
                            check_value = registers['Esp'] + 0x4  # Bypass
                            if check_value == handle:
                                process.write_dword(check_value, 0)

                        else:
                            if thread.get_register('Rcx') == handle:
                                thread.set_register('Rcx', 0)  # Bypass

                        Extract.Printer_Bypass("NtClose")



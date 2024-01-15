#-*- coding:utf-8 -*-
from winappdbg import *

import Debugging
import Extract

class AntiDebugging_Check(object):

    def peb_beingdebugged(self, event, peb_beingdebugged):
        if (peb_beingdebugged == 1): # Check
            process = event.get_process()

            peb_address = process.get_peb_address()

            Extract.Printer_Check("PEB!BeingDebugged")

            process.write_char(peb_address + 0x2, 0)  # Bypass

            Extract.Printer_Bypass("PEB!BeingDebugged")

    def peb_NtGlobalFlag(self, event, peb_ntglobalflag, ntglobalflag_address):
        if (peb_ntglobalflag == 0x70): # Check
            process = event.get_process()

            Extract.Printer_Check("PEB!NtGlobalFlag")

            process.write_char(ntglobalflag_address, 0) # Bypass

            Extract.Printer_Bypass("PEB!NtGlobalFlag")

    # Heap Flag -> Need to check HeapGrowable 
    def peb_HeapFlag(self, event, peb_heapflag, offset):
        process = event.get_process()

        Major_Version = win32.GetVersionExA().dwMajorVersion

        if (Major_Version < 6): # Before Vista
            offset = offset - 0x4 # 0x40 or 0x70
            try:
                heap_flag_check_value = process.read_dword(peb_heapflag + offset)

                if (heap_flag_check_value != 0): # Check
                    Extract.Printer_Check("PEB!HeapFlag")

                    process.write_dword(peb_heapflag + offset, 0) # Bypass

                    Extract.Printer_Bypass("PEB!HeapFlag")

            except WindowsError: # Exception
                pass

        else:
            try:
                heap_flag_check_value = process.read_dword(peb_heapflag + offset)

                if (heap_flag_check_value != 0): # Check
                    Extract.Printer_Check("PEB!HeapFlag")

                    process.write_dword(peb_heapflag + offset, 0) # Bypass

                    Extract.Printer_Bypass("PEB!HeapFlag")

            except WindowsError:
                pass

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

    def CheckRemoteDebuggerPresent(self, event, second, return_address):

        pid = event.get_pid()

        self.remote_second_address = second
        self.remote_RemoteDebuggerPresent_return_address = return_address

        event.debug.break_at(pid, self.remote_RemoteDebuggerPresent_return_address, self.CheckRemoteDebuggerPresent_Check_and_Bypass) # return addreses breakpoint set

    def CheckRemoteDebuggerPresent_Check_and_Bypass(self, event):

        process = event.get_process()
        pid = event.get_pid()

        CheckRemoteDebuggerPresent_Check = process.peek_int(self.remote_second_address)

        if CheckRemoteDebuggerPresent_Check == 1: # Check
            Extract.Printer_Check("CheckRemoteDebuggerPresent")

            process.write_int(self.remote_second_address, 0) # Bypass

            CheckRemoteDebuggerPresent_Bypass = process.peek_int(self.remote_second_address)

            if CheckRemoteDebuggerPresent_Bypass == 0: # Bypass Check
                Extract.Printer_Bypass("CheckRemoteDebuggerPresent")

            else:
                Extract.Printer_NotBypass("CheckRemoteDebuggerPresent")

        else: # Not Check
            Extract.Printer_NotCheck("CheckRemoteDebuggerPresent")

        event.debug.dont_break_at(pid, self.remote_return_address) # breakpoint delete

    def NtQueryInformationProcess_Flags(self, event, flags, buffer, return_address):

        pid = event.get_pid()

        self.remote_NtQuery_flags = flags
        self.remote_NtQuery_buffer = buffer
        self.remote_NtQueryInformation_return_address = return_address

        event.debug.break_at(pid, self.remote_NtQueryInformation_return_address, self.NtQueryInformationProcess_Flags_Check_and_Bypass) # return address breakpoint set

    def NtQueryInformationProcess_Flags_Check_and_Bypass(self, event):

        process = event.get_process()
        pid = event.get_pid()
        bits = Extract.check_bit(event)

        CheckFlags_Value = self.remote_NtQuery_flags

        if CheckFlags_Value == 0x7: # Check Debug Port
            if bits == 32:
                CheckBuffer_Value = process.read_dword(self.remote_NtQuery_buffer)

                if CheckBuffer_Value == 0xffffffff: # Debugging Check 32
                    Extract.Printer_Check("NtQueryInformationProcess DebugPort")

                    process.write_dword(self.remote_NtQuery_buffer, 0) # Bypass

                    Extract.Printer_Bypass("NtQueryInformationProcess DebugPort")

                else:
                    Extract.Printer_NotCheck("NtQueryInformationProcess DebugPort")

            else:
                CheckBuffer_Value = process.read_qword(self.remote_NtQuery_buffer)

                if CheckBuffer_Value == 0xffffffffffffffff: # Debugging Check 64
                    Extract.Printer_Check("NtQueryInformationProcess DebugPort")

                    process.write_dword(self.remote_NtQuery_buffer, 0) # Bypass

                    Extract.Printer_Bypass("NtQueryInformationProcess DebugPort")

                else:
                    Extract.Printer_Check("NtQueryInformationProcess DebugPort")

        if CheckFlags_Value == 0x1E: # Check Object Handle
            if bits == 32:
                CheckBuffer_Value = process.read_dword(self.remote_NtQuery_buffer)

                if CheckBuffer_Value != 0: # Debugging Check 32
                    Extract.Printer_Check("NtQueryInformationProcess ObjectHandle")

                    process.write_dword(self.remote_NtQuery_buffer, 0) # Bypass

                    Extract.Printer_Bypass("NtQueryInformationProcess ObjectHandle")

                else:
                    Extract.Printer_NotCheck("NtQueryInformationProcess ObjectHandle")

            else:
                CheckBuffer_Value = process.read_qword(self.remote_NtQuery_buffer)

                if CheckBuffer_Value != 0: # Debugging Check 64
                    Extract.Printer_Check("NtQueryInformationProcess ObjectHandle")

                    process.write_qword(self.remote_NtQuery_buffer, 0)  # Bypass

                    Extract.Printer_Bypass("NtQueryInformationProcess ObjectHandle")

                else:
                    Extract.Printer_NotCheck("NtQueryInformationProcess ObjectHandle")

        if CheckFlags_Value == 0x1F: # Check Flags
            CheckBuffer_Value = process.read_int(self.remote_NtQuery_buffer)

            if CheckBuffer_Value == 0: # Debugging Check
                Extract.Printer_Check("NtQueryInformationProcess Flags")

                process.write_int(self.remote_NtQuery_buffer, 1) # Bypass

                Extract.Printer_Bypass("NtQueryInformationProcess Flags")

            else:
                Extract.Printer_NotCheck("NtQueryInformationProcess Flags")






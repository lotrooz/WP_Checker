#-*- coding:utf-8 -*-
from winappdbg import *

import Debugging
import Extract

class AntiDebugging_Check(object):

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






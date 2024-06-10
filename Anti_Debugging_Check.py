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

    def peb_NtGlobalFlag(self, event, NtGlobalFlag_address):

        process = event.get_process()
        pid = event.get_pid()
        bits = Extract.check_bit(event)

        if bits == 32:
            event.debug.break_at(pid, NtGlobalFlag_address + 0x6, self.peb_NtGlobalFlag_Check)

        else:
            event.debug.break_at(pid, NtGlobalFlag_address + 0x9, self.peb_NtGlobalFlag_Check)

        win32.CreateRemoteThread(process.get_handle(), 0, 0, NtGlobalFlag_address, 0, 0)


    def peb_NtGlobalFlag_Check(self, event):

        context = event.get_thread().get_context()
        bits = Extract.check_bit(event)

        if bits == 32:
            check_ntglobal = context['Eax'] + 0x68
            read_ntglobal = event.get_process().read_char(check_ntglobal)

        else:
            check_ntglobal = context['Rax'] + 0xBC
            read_ntglobal = event.get_process().read_char(check_ntglobal)

        if read_ntglobal == 0x70:
            Extract.Printer_Check("PEB!NtGlobalFlag")

            event.get_process().write_char(check_ntglobal, 0)
            Extract.Printer_Bypass("PEB!NtGlobalFlag")



    # Heap Flag -> Need to check HeapGrowable
    def peb_HeapFlag(self, event, HeapFlag_address, Major_Version):
        process = event.get_process()
        pid = event.get_pid()
        bits = Extract.check_bit(event)
        self.version_check = Major_Version

        if bits == 32:
            event.debug.break_at(pid, HeapFlag_address + 0xC, self.peb_HeapFlag_Check)

        else:
            event.debug.break_at(pid, HeapFlag_address + 0xD, self.peb_HeapFlag_Check)

        win32.CreateRemoteThread(process.get_handle(), 0, 0, HeapFlag_address, 0, 0)

    def peb_HeapFlag_Check(self, event):
        context = event.get_thread().get_context()
        bits = Extract.check_bit(event)

        if bits == 32: # 32 bit Version
            if (self.version_check < 6): # Before Vista
                check_heap_flag = context['Eax'] + 0xC
                check_heap_force = context['Eax'] + 0x10
                read_heap_flag = event.get_process().read_dword(check_heap_flag)
                read_heap_force = event.get_process().read_dword(check_heap_force)

            else:
                check_heap_flag = context['Eax'] + 0x40
                check_heap_force = context['Eax'] + 0x44
                read_heap_flag = event.get_process().read_dword(check_heap_flag)
                read_heap_force = event.get_process().read_dword(check_heap_force)

        else: # 64 bit Version
            if (self.version_check < 6): # Before Vista
                check_heap_flag = context['Rax'] + 0x14
                check_heap_force = context['Rax'] + 0x18
                read_heap_flag = event.get_process().read_dword(check_heap_flag)
                read_heap_force = event.get_process().read_dword(check_heap_force)

            else:
                check_heap_flag = context['Rax'] + 0x70
                check_heap_force = context['Rax'] + 0x74
                read_heap_flag = event.get_process().read_dword(check_heap_flag)
                read_heap_force = event.get_process().read_dword(check_heap_force)

        if (read_heap_flag != 2 or read_heap_force != 0):
            Extract.Printer_Check("PEB!HeapFlag")

            event.get_process().write_dword(check_heap_flag, 0x2) # bypass
            event.get_process().write_dword(check_heap_force, 0x0)

            Extract.Printer_Bypass("PEB!HeapFlag")

    def IsDebuggerPresent(self, event, return_value):

        if return_value == 1:
            Extract.Printer_Check("IsDebuggerPresent")
            return True

    def IsDebuggerPresent_Bypass(self, event): # Bypass 인자에선 이미 위에 PEB_BeingDebugged에서 변경하여 이쪽 이벤트 나오진 않음

        thread = event.get_thread()

        bits = Extract.check_bit(event)

        if bits == 32: # 32bit bypass
            thread.set_register("Eax", 0)

            if Extract.registers(event,"Eax") == 0:
                Extract.Printer_Bypass("IsDebuggerPresent")


        else: # 64bit bypass
            thread.set_register("Rax", 0)

            if Extract.registers(event, "Rax") == 0:
                Extract.Printer_Bypass("IsDebuggerPresent")


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

            event.debug.break_at(pid, self.NtQuery_return_address, self.NtQueryInformationProcess_Check)

        elif (CheckFlags_Value == 0x1E):

            event.debug.break_at(pid, self.NtQuery_return_address, self.NtQueryInformationProcess_Check)

        elif (CheckFlags_Value == 0x1F):

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
                    check_value = registers['Esp'] + 0x8 # Bypass
                    process.write_dword(check_value, 0)

                else:
                    thread.set_register('Rdx', 0) # Bypass Check

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
        #DebuggerNotPresent = process.read_char(check_system_info + 0x1)   #ah , Debugging -> 0

        if DebuggerEnabled:
            Extract.Printer_Check("NtQuerySystemInformation")

            if self.NtSystem_bypass:  # bypass
                process.write_char(check_system_info, 0)  # DebuggerEnabled -> 0
                #process.write_char(check_system_info, 1)  # DebuggerNotPresent -> 1

                Extract.Printer_Bypass("NtQuerySystemInformation")
        #if (DebuggerEnabled or not DebuggerNotPresent):


    def NtClose_Check(self, event, handle, bypass):

        process = event.get_process()
        thread = event.get_thread()
        registers = thread.get_context()
        bits = Extract.check_bit(event)

        try:
            win32.GetHandleInformation(handle)

        except Exception as e:
            if isinstance(e, WindowsError):
                if e.winerror == 6:         # invalid handle Check

                    if bits == 32:
                        check_value = registers['Esp'] + 0x4
                        if (check_value == handle and check_value > 0xFFFF): # ???
                            Extract.Printer_Check("NtClose")

                            if bypass: # bypass
                                process.write_dword(check_value, 0)
                                Extract.Printer_Bypass("NtClose")

                    else:
                        check_value = registers['Rcx']
                        if (check_value == handle and check_value > 0xFFFF):
                            Extract.Printer_Check("NtClose")

                            if bypass: # bypass
                                thread.set_register('Rcx', 0)
                                Extract.Printer_Bypass("NtClose")

    def NtOpenProcess_Flags(self, event, return_address, bypass):

        pid = event.get_pid()

        self.NtOpen_return_address = return_address
        self.NtOpen_bypass = bypass

        event.debug.break_at(pid, self.NtOpen_return_address, self.NtOpenProcess_Check)

    def NtOpenProcess_Check(self, event):

        bits = Extract.check_bit(event)
        pid = event.get_pid()
        thread = event.get_thread()
        registers = thread.get_context()

        if bits == 32:
            return_value = registers['Eax']

            if return_value == 0: # STATUS_SUCCESS
                Extract.Printer_Check("NtOpenProcess")

                if self.NtOpen_bypass:
                    thread.set_register('Eax', 0xC0000022) # STATUS_ACCESS_DENIED
                    Extract.Printer_Bypass("NtOpenProcess")

        else:
            return_value = registers['Rax']

            if return_value == 0: # STATUS_SUCCESS
                Extract.Printer_Check("NtOpenProcess")

                if self.NtOpen_bypass:
                    thread.set_register('Rax', 0xC0000022)  # STATUS_ACCESS_DENIED
                    Extract.Printer_Bypass("NtOpenProcess")

        event.debug.dont_break_at(pid, self.NtOpen_return_address)

    def LdrLoadDll_Check(self, event, process_name, path_file, bypass):

        bits = Extract.check_bit(event)

        if process_name == path_file:
            try:
                win32.CreateProcessA(path_file, win32.GENERIC_READ, 0, 0, win32.OPEN_EXISTING, 0, 0)

            except Exception as e:
                if isinstance(e, WindowsError):
                    if e.winerror == 6: # Invalid Handle
                        Extract.Printer_Check("LdrLoadDll")
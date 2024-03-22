#-*- coding:utf-8 -*-
from winappdbg import *

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

        print ("333333")

        print (peb_heapflag)
        print (hex(offset))

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
            print("444444")
            #try:
            #heap_flag_check_value = process.read_dword(peb_heapflag + offset)

            #print (heap_flag_check_value)

            #if (heap_flag_check_value != 0): # Check
            #    Extract.Printer_Check("PEB!HeapFlag")

            #    process.write_dword(peb_heapflag + offset, 0) # Bypass

            #    Extract.Printer_Bypass("PEB!HeapFlag")

            #except WindowsError:
            #    pass

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

        event.debug.break_at(pid, self.remote_RemoteDebuggerPresent_return_address, self.CheckRemoteDebuggerPresent_Check_and_Bypass) # return addreses breakpoint set

    def CheckRemoteDebuggerPresent_Check_and_Bypass(self, event):

        process = event.get_process()

        CheckRemoteDebuggerPresent_Check = process.peek_int(self.remote_second_address)

        if CheckRemoteDebuggerPresent_Check == 1: # Check
            Extract.Printer_Check("CheckRemoteDebuggerPresent")

            if self.remote_bypass:
                process.write_int(self.remote_second_address, 0) # Bypass

                Extract.Printer_Bypass("CheckRemoteDebuggerPresent")



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

    def NtSetInformationThread_Check_and_Bypass(self, event, threadinfo_class):

        if threadinfo_class == 0x11:

            Extract.Printer_Check("NtSetInformationThread")

            process = event.get_process()
            thread = event.get_thread()
            registers = thread.get_context()
            bits = Extract.check_bit(event)

            if bits == 32:
                check_value = registers['Esp'] + 0x4 # Bypass
                process.write_int(check_value, 0)

            else:
                thread.set_register('Rdx', 0) # Bypass

            Extract.Printer_Bypass("NtSetInformationThread")

    def NtQuerySystemInformation_Data(self, event, systeminformatinoclass, systeminformation, return_address):
        pid = event.get_pid()

        self.NtQueryinfo_class = systeminformatinoclass
        self.NtQueryinfo = systeminformation
        self.NtQuery_return_address = return_address

        if (self.NtQueryinfo_class == 0x23):
            event.debug.break_at(pid, self.NtQuery_return_address, self.NtQuerySystemInformation_Check_and_Bypass)

    def NtQuerySystemInformation_Check_and_Bypass(self, event):

        process = event.get_process()
        check_queryinfo = self.NtQueryinfo

        DebuggerEnabled = process.read_char(check_queryinfo)    # al , Debugging -> 1
        DebuggerNotPresent = process.read_char(check_queryinfo + 0x1)   #ah , Debugging -> 0

        if (DebuggerEnabled or not DebuggerNotPresent):
            Extract.Printer_Check("NtQuerySystemInformation")

            process.write_char(check_queryinfo, 0) # DebuggerEnabled -> 0
            process.write_char(check_queryinfo, 1) # DebuggerNotPresent -> 1

            Extract.Printer_Bypass("NtQuerySystemInformation")

    def NtClose_Check_and_Bypass(self, event, handle):

        try:
            status = win32.GetHandleInformation(handle)

        except Exception as e:
            if isinstance(e, WindowsError):
                if e.winerror == 6:         # invalid handle
                    print (hex(handle))
                    print ("Windows Error Occured : ", e.strerror)

                    process = event.get_process()
                    thread = event.get_thread()
                    registers = thread.get_context()

                    bits = Extract.check_bit(event)

                    self.handle = 0
                    '''
                    if bits == 32:
                        check_value = registers['Esp'] + 0x4  # Bypass
                        process.write_dword(check_value, 0)
                        
                        print (process.read_dword(check_value))

                    else:
                        thread.set_register('Rdx', 0)  # Bypass
                        print (process.read_dword(registers['Rdx']))
                    '''







        #print (status)

        #if not (status):
        #    print ("abbbbbbbbbbbbewrwe")


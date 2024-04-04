#-*- coding:utf-8 -*-
from winappdbg import *

import time
import Extract
import Anti_Debugging
import Anti_VM
import traceback

VirtualBox_Reg_List = ["HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_80EE*", "HKLM\HARDWARE\ACPI\DSDT\VBOX__", "HKLM\HARDWARE\ACPI\FADT\VBOX__", "HKLM\HARDWARE\ACPI\RSDT\VBOX__", "HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions", "HKLM\SYSTEM\ControlSet001\Services\VBoxGuest", "HKLM\SYSTEM\ControlSet001\Services\VBoxMouse", "HKLM\SYSTEM\ControlSet001\Services\VBoxService", "HKLM\SYSTEM\ControlSet001\Services\VBoxSF", "HKLM\SYSTEM\ControlSet001\Services\VBoxVideo"]
VMWare_Reg_List = ["HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD*", "HKCU\SOFTWARE\VMware, Inc.\VMware Tools", "HKLM\SOFTWARE\VMware, Inc.\VMware Tools", "HKLM\SYSTEM\ControlSet001\Services\vmdebug", "HKLM\SYSTEM\ControlSet001\Services\vmmouse", "HKLM\SYSTEM\ControlSet001\Services\VMTools", "HKLM\SYSTEM\ControlSet001\Services\VMMEMCTL", "HKLM\SYSTEM\ControlSet001\Services\vmware", "HKLM\SYSTEM\ControlSet001\Services\vmci", "HKLM\SYSTEM\ControlSet001\Services\vmx86", "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_IDE_CD*", "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_SATA_CD*", "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_IDE_Hard_Drive*", "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_SATA_Hard_Drive*"]
#VirtualBox_File_List = ["C:\\WINDOWS\\system32\\vbox*.dll", "C:\\WINDOWS\\system32\\drivers\\vbox*.sys", "C:\\Program files\\Oracle\\VirtualBox Guest Additions"]
class AntiVM_Check(object):

    HKEY_CLASSES_ROOT = System.registry._hives[0]
    HKEY_CURRENT_CONFIG = System.registry._hives[1]
    HKEY_CURRENT_USER = System.registry._hives[2]
    HKEY_LOCAL_MACHINE = System.registry._hives[3]
    HKEY_PERFORMANCE_DATA = System.registry._hives[4]
    HKEY_USERS = System.registry._hives[5]

    def GetSystemInfo(self, event, system_info_structure, return_address, bypass): # CPU Core Check
        pid = event.get_pid()

        self.system_info_structure_pointer = system_info_structure
        self.system_info_return_address = return_address
        self.system_info_bypass = bypass

        event.debug.break_at(pid, self.system_info_return_address, self.GetSystemInfo_Check)

    def GetSystemInfo_Check(self, event): # CPU Core Check & Bypass

        process = event.get_process()
        bits = Extract.check_bit(event)

        if bits == 32:
            check_core_number = process.read_dword(self.system_info_structure_pointer + 0x18)

        else:
            check_core_number = process.read_dword(self.system_info_structure_pointer + 0x20)

        if check_core_number < 2:
            Extract.Printer_Check("CPU Core Number is too small")

            if self.system_info_bypass:
                if bits == 32:
                    process.write_dword(self.system_info_structure_pointer + 0x1C, 4) # Change Core Number 4

                else:
                    process.write_dword(self.system_info_structure_pointer + 0x20, 4) # Change Core Number 4

                Extract.Printer_Bypass("CPU Core Number is adjusted")

    def GlobalMemoryStatus(self, event, memory_status_structure, return_address, bypass): # RAM Check
        pid = event.get_pid()

        self.memory_status_pointer = memory_status_structure
        self.memory_status_return_address = return_address
        self.memory_status_bypass = bypass

        event.debug.break_at(pid, self.memory_status_return_address, self.GlobalMemoryStatus_Check)

    def GlobalMemoryStatus_Check(self, event): # RAM Check & Bypass

        process = event.get_process()

        check_ram_size = process.read_qword(self.memory_status_pointer + 0x8)

        if check_ram_size < (2048 * 1024 * 1024):
            Extract.Printer_Check("RAM Size is too small")

            if self.memory_status_bypass:
                process.write_qword(self.memory_status_pointer + 0x8, (4096 * 1024 * 1024)) # Change 4GB

                Extract.Printer_Bypass("RAM Size is adjusted")

    def DeviceIoControl(self, event, dwiocontrol_code, disk_geometry_structure, return_address, bypass):
        pid = event.get_pid()

        self.disk_geometry_pointer = disk_geometry_structure
        self.disk_geometry_return_address = return_address
        self.disk_geometry_bypass = bypass

        if (dwiocontrol_code == 0x70000): # IOCTL_DISK_GET_DRIVE_GEOMETRY
            event.debug.break_at(pid, self.disk_geometry_return_address, self.DeviceIoControl_Check)

    def DeviceIoControl_Check(self, event): # fix ...

        process = event.get_process()

        disk_geometry_cylinders_lowpart = process.read_dword(self.disk_geometry_pointer + 0x10)
        disk_geometry_cylinders_highpart = process.read_dword(self.disk_geometry_pointer + 0x14)

        disk_geometry_cylinders_quadpart = disk_geometry_cylinders_lowpart + (disk_geometry_cylinders_highpart * 0x100000000) # union_structure

        disk_geometry_trackspercylinder = process.read_dword(self.disk_geometry_pointer + 0x1C)
        disk_geometry_sectorespertrack = process.read_dword(self.disk_geometry_pointer + 0x20)
        disk_geometry_bytespersector = process.read_dword(self.disk_geometry_pointer + 0x24)

        hdd_size = disk_geometry_cylinders_quadpart * disk_geometry_trackspercylinder * disk_geometry_sectorespertrack * disk_geometry_bytespersector / 1024 / 1024 / 1024

        print (disk_geometry_cylinders_lowpart)
        print (disk_geometry_cylinders_highpart)

        print (hdd_size)

        #test1 = process.read_dword(self.disk_geometry_pointer)

        #test2 = process.read_dword(test1 + 0x16)

        #print (hex(test1))

        #print (hex(test2))

    def FindFirstFileW_Check(self, event, lpfilename, bypass): # File Check API

        process = event.get_process()

        check_list = ["C:\\WINDOWS\\system32\\vbox", "C:\\WINDOWS\\system32\\drivers\\vbox", "C:\\Program files\\Oracle\\VirtualBox Guest Additions", "C:\\WINDOWS\\system32\\vm", "C:\\WINDOWS\\system32\\drivers\\vm"]

        find_filename = process.peek_string(lpfilename, fUnicode=True)

        for i in check_list:
            if i.lower() in find_filename.lower(): # Check
                Extract.Printer_Check("Virtual Machine File Check")

                if bypass:
                    process.poke_char(int(lpfilename), 0x30) # Change First Byte to Zero

                    Extract.Printer_Bypass("Virtual Machine File Check") # Bypass

    def RegOpenKeyExW_Check(self, event, hkey, lpsubkey, bypass):

        process = event.get_process()

        reg_string = process.peek_string(lpsubkey, fUnicode=True)

        # VirtualBox Target
        # 1. HKLM\SYSTEM\ControlSet001\Services\VBox*
        # 2. HKLM\HARDWARE\ACPI\???T\VBOX__
        # 3. HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions

        # VMware Target
        # 1. SYSTEM\ControlSet001\Services\vm*
        # 2. HK?U\SOFTWARE\VMware, Inc.\VMware Tools

        check_list = ["SYSTEM\\ControlSet001\\Services\\VBox", "SOFTWARE\\Oracle\\VirtualBox Guest Additions", "VBOX__", "SYSTEM\\ControlSet001\\Services\\vm", "SOFTWARE\\VMware"]

        for i in check_list:
            if i.lower() in reg_string.lower(): # Check
                Extract.Printer_Check("Virtual Machine Reg Check")

                if bypass:

                    process.poke_char(lpsubkey, 0x30) # Change First Byte to Zero

                    Extract.Printer_Bypass("Virtual Machine Reg Check") # Bypass

    def SetupDiGetDeviceRegistryPropertyW(self, event, property_buffer, return_address, bypass):

        pid = event.get_pid()

        self.setupdi_property_buffer = property_buffer
        self.setupdi_return_address = return_address
        self.setupdi_bypass = bypass

        event.debug.break_at(pid, self.setupdi_return_address, self.SetupDiGetDeviceRegistryPropertyW_Check)

    def SetupDiGetDeviceRegistryPropertyW_Check(self, event, property_buffer):

        process = event.get_process()

        device_string = process.peek_string(self.setupdi_property_buffer, fUnicode=True)

        check_list = ["vbox", "vmware", "Samsung"] # Samsung is temp

        for i in check_list:
            if i.lower() in device_string.lower(): # Check
                Extract.Printer_Check("Virtual Machine HDD Device Check")

                if self.setupdi_bypass:
                    process.poke_char(property_buffer, 0x30) # Change First byte to Zero

                    Extract.Printer_Bypass("Virtual Machine HDD Device Check") # Bypass
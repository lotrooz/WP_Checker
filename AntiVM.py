#-*- coding:utf-8 -*-
from winappdbg import *

import Debugging
import Extract

VirtualBox_Reg_List = ["HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_80EE*", "HKLM\HARDWARE\ACPI\DSDT\VBOX__", "HKLM\HARDWARE\ACPI\FADT\VBOX__", "HKLM\HARDWARE\ACPI\RSDT\VBOX__", "HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions", "HKLM\SYSTEM\ControlSet001\Services\VBoxGuest", "HKLM\SYSTEM\ControlSet001\Services\VBoxMouse", "HKLM\SYSTEM\ControlSet001\Services\VBoxService", "HKLM\SYSTEM\ControlSet001\Services\VBoxSF", "HKLM\SYSTEM\ControlSet001\Services\VBoxVideo"]
VMWare_Reg_List = ["HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD*", "HKCU\SOFTWARE\VMware, Inc.\VMware Tools", "HKLM\SOFTWARE\VMware, Inc.\VMware Tools", "HKLM\SYSTEM\ControlSet001\Services\vmdebug", "HKLM\SYSTEM\ControlSet001\Services\vmmouse", "HKLM\SYSTEM\ControlSet001\Services\VMTools", "HKLM\SYSTEM\ControlSet001\Services\VMMEMCTL", "HKLM\SYSTEM\ControlSet001\Services\vmware", "HKLM\SYSTEM\ControlSet001\Services\vmci", "HKLM\SYSTEM\ControlSet001\Services\vmx86", "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_IDE_CD*", "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_SATA_CD*", "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_IDE_Hard_Drive*", "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_SATA_Hard_Drive*"]

class AntiVM_Check(object):

    def GetSystemInfo_Data(self, event, system_info_structure, return_address): # CPU Core Check
        pid = event.get_pid()

        self.system_info_structure_pointer = system_info_structure
        self.system_info_return_address = return_address

        event.debug.break_at(pid, self.system_info_return_address, self.GetSystemInfo_Check_Bypass)

    def GetSystemInfo_Check_Bypass(self, event): # CPU Core Check & Bypass

        process = event.get_process()
        bits = Extract.check_bit(event)

        if bits == 32:
            check_core_number = process.read_dword(self.system_info_structure_pointer + 0x18)

        else:
            check_core_number = process.read_dword(self.system_info_structure_pointer + 0x20)

        if check_core_number < 2:
            Extract.Printer_Check("CPU Core Number is too small")

            if bits == 32:
                process.write_dword(self.system_info_structure_pointer + 0x1C, 4) # Change Core Number 4

            else:
                process.write_dword(self.system_info_structure_pointer + 0x20, 4) # Change Core Number 4

            Extract.Printer_Bypass("CPU Core Number is adjusted")

    def GlobalMemoryStatus_Data(self, event, memory_status_structure, return_address): # RAM Check
        pid = event.get_pid()

        self.memory_status_pointer = memory_status_structure
        self.memory_status_return_address = return_address

        event.debug.break_at(pid, self.memory_status_return_address, self.GlobalMemoryStatus_Check_Bypass)

    def GlobalMemoryStatus_Check_Bypass(self, event): # RAM Check & Bypass

        process = event.get_process()

        check_ram_size = process.read_qword(self.memory_status_pointer + 0x8)

        if check_ram_size < (2048 * 1024 * 1024):
            Extract.Printer_Check("RAM Size is too small")

            process.write_qword(self.memory_status_pointer + 0x8, (4096 * 1024 * 1024)) # Change 4GB

            Extract.Printer_Bypass("RAM Size is adjusted")

    def DeviceIoControl_Data(self, event, disk_geometry_structure, return_address):
        pid = event.get_pid()

        self.disk_geometry_pointer = disk_geometry_structure
        self.disk_geometry_return_address = return_address

        event.debug.break_at(pid, self.disk_geometry_return_address, self.DeviceIoControl_Check_Bypass)

    def DeviceIoControl_Check_Bypass(self, event):

        process = event.get_process()


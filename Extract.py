from winappdbg import *
import Anti_Debugging
import Anti_VM


def anti_create_event_handler(param1):
    return Anti_Debugging.Anti_Debugging_Start(param1)

def anti_vm_create_event_handler(param1):
    return Anti_VM.Anti_VM_Start(param1)

def get_all(event): # process, pid, tid, module, thread, registers
    process = event.get_process()
    pid = event.get_pid()
    tid = event.get_tid()
    module = event.get_module()
    thread = event.get_thread()
    register = thread.get_context()

    return process, pid, tid, module, thread, register

def check_bit(event): # Check Bit
    bits = event.get_process().get_bits()

    return bits

def check_csp(event, bits): # Check CSP
    thread = event.get_thread()

    if bits == 32:
        return thread.read_stack_dwords(1)[0]

    elif bits == 64:
        return thread.read_stack_qwords(1)[0]

def registers(event, registers): # Specific Register Extract
    thread = event.get_thread()
    register = thread.get_context()

    return register[registers]

def check_32bit_eip_address(eip, breakpoint_address): # EIP = Current BreakPoint Check
    if eip == breakpoint_address:
        return True
    else:
        return False

def check_64bit_eip_address(rip, breakpoint_address): # RIP = Current BreakPoint Check
    if rip == breakpoint_address:
        return True
    else:
        return False

def Printer_Check(Name):
    print ("\n[+] Detection !!")
    print ("[+] ----------------------------")
    print ("[+] " + Name + " Detected !!")
    print ("[+] ----------------------------")

def Printer_Check_Logic(Name):
    print("\n[+] Check_Logic !!")
    print("[+] ----------------------------")
    print("[+] " + Name + " Check_Logic !!")
    print("[+] ----------------------------")

def Printer_Bypass(Name):
    print ("\n[+] Bypass !!")
    print ("[+] ----------------------------")
    print ("[+] " + Name + " Bypass !!")
    print ("[+] ----------------------------")

def Printer_NotBypass(Name):
    print("\n[+] Not Detection !!")
    print("[+] ----------------------------")
    print("[+] " + Name + " Not Bypass !!")
    print("[+] ----------------------------")




class return_value(object):
    def find_return_value(self, event):


        thread = event.get_thread()
        tid = thread.get_tid()
        stack_top = thread.get_sp()

        bits = check_bit(event)

        if bits == 32:
            return_address = thread.read_stack_dwords(1)

        else:
            return_address = thread.read_stack_qwords(1)

        try:
            if bits == 32:
                event.debug.stalk_variable(tid, stack_top, 4, self.returning)

            else:
                event.debug.stalk_variable(tid, stack_top, 8, self.returning)

        except RuntimeError:
            event.debug.stalk_variable(event.get_pid(), return_address, self.returning_2)

    def returning(self, event):

        variable_address = event.breakpoint.get_address()

        event.debug.dont_stalk_variable(event.get_tid(), variable_address)

        registers = event.get_thread().get_context()

        if check_bit(event) == 32:
            return_value = registers['Eax']
        else:
            return_value = registers['Rax']

        self.return_val = return_value

        print (self.return_val)

    def returning_2(self, event):

        return_address = event.breakpoint.get_address()

        event.debug.dont_stalk_at(event.get_pid(), return_address)

        registers = event.get_thread().get_context()

        if check_bit(event) == 32:
            return_value = registers['Eax']
        else:
            return_value = registers['Rax']



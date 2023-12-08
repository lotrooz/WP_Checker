from winappdbg import *
from winappdbg.win32.defines import *

import AntiDebugging
import Extract

class Debugging_PE(EventHandler):

    AntiDebugging_Checker = AntiDebugging.AntiDebugging_Check()

    apiHooks = {

        'kernel32.dll' : [
            ('IsDebuggerPresent', 0),
            ('CheckRemoteDebuggerPresent', 2),
            ('OutputDebugStringA', 1),
        ],

    }

    def create_process(self, event):
        process, pid, tid, module, thread, registers = Extract.get_all(event)

        print (event.get_filename())

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

def Debugging_Start(process):

    with Debug(Debugging_PE(), bKillOnExit=True) as debug:
        debug.execv(process)

        debug.loop()

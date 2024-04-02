Anti Debugging, Anti VM Check & Bypass

Python Module : Winappdbg

|Detect|Check|Bypass|
|------|---|---|
|PEB!BeingDebugged|OK|OK|
|PEB!NtGlobalFlag|OK|OK|
|PEB!HeapFlag|Fix|Fix|
|IsDebuggerPresent|OK|OK|
|CheckRemoteDebuggerProcess|OK|OK|
|NtQueryInformationProcess_DebugPort|OK|OK|
|NtQueryInformationProcess_Object Handle|OK|OK|
|NtQueryInformationProcess_Flags|OK|OK|
|NtSetInformationThread|OK|OK|
|NtQuerySystemInformation|OK|OK|
|NtOpenProcess|OK|OK|
|NtClose|OK|OK|
|ldrloadlibrary|OK|X|



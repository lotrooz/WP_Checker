Anti Debugging Check & Bypass, Anti VM ing

Python Module : Winappdbg

|Detect|Check|Bypass|
|------|---|---|
|PEB!BeingDebugged|OK|OK|
|PEB!NtGlobalFlag|OK|OK|
|PEB!HeapFlag|OK|OK|
|IsDebuggerPresent|OK|OK|
|CheckRemoteDebuggerProcess|OK|OK|
|NtQueryInformationProcess_DebugPort|OK|OK|
|NtQueryInformationProcess_Object Handle|OK|OK|
|NtQueryInformationProcess_Flags|OK|OK|
|NtSetInformationThread|OK|OK|
|NtQuerySystemInformation|OK|OK|
|NtOpenProcess|Code O, Test|Code O, Test|
|NtClose|Code O, Test|Code O, Test|
|ldrloadlibrary|Code O, Test|X|



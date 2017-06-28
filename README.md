# WibuDebugHook

Injectable DLL that helps with debugging Wibu CodeMeter.

A hollowed process is started with `CreateProcessA`, this is the relevant code:

```c++
DWORD __stdcall DebugLoop(int a1, int a2, char *a3, int a4)
{
  DWORD result; // eax@2
  int pid; // eax@3
  int hThread; // esi@12
  DEBUG_EVENT event; // [sp+4h] [bp-330h]@7
  CONTEXT ctx; // [sp+64h] [bp-2D0h]@12

  if ( !sub_404D80() )
    return -1;
  pid = sub_404FF2(a3);
  if ( !pid )
    return -2;
  if ( DebugActiveProcess(pid) )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( !WaitForDebugEvent(&event, 500) )
          ;
        if ( event.dwDebugEventCode == 1 )
          break;
        result = event.dwDebugEventCode - EXIT_PROCESS_DEBUG_EVENT;
        if ( event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT )
          return result;
LABEL_27:
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
      }
      hThread = OpenThread(0x1FFFFF, 0, event.dwThreadId);
      ctx.ContextFlags = CONTEXT_ALL;
      GetThreadContext(hThread, &ctx);
      if ( event.u.Exception.ExceptionRecord.ExceptionCode > 0xC000001D )
      {
        if ( event.u.Exception.ExceptionRecord.ExceptionCode == 0xC0000094 )
        {
          ctx.Ebx = 7;
          goto LABEL_26;
        }
        if ( event.u.Exception.ExceptionRecord.ExceptionCode == 0xC0000096 )
        {
          ctx.Eip += 3;
          goto LABEL_26;
        }
      }
      else
      {
        if ( event.u.Exception.ExceptionRecord.ExceptionCode == 0xC000001D )
        {
          ctx.Eip += 2;
          goto LABEL_26;
        }
        if ( event.u.Exception.ExceptionRecord.ExceptionCode == 0x406D1388
          || event.u.Exception.ExceptionRecord.ExceptionCode == 0x80000003 )
        {
          goto LABEL_26;
        }
        if ( event.u.Exception.ExceptionRecord.ExceptionCode == 0xC0000005
          && (event.u.Exception.ExceptionRecord.NumberParameters != 2
           || event.u.Exception.ExceptionRecord.ExceptionInformation[1] >= 2
           && event.u.Exception.ExceptionRecord.ExceptionInformation[1] <= 6) )
        {
          ctx.Eip += 7;
LABEL_26:
          SetThreadContext(hThread, &ctx);
          CloseHandle2(hThread);
          goto LABEL_27;
        }
      }
      ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
      CloseHandle2(hThread);
    }
  }
  return -3;
}
```

When debugging, `DebugActiveProcess` will fail, thus killing the process. This causes a check with `OpenProcess` to fail later. In addition to injecting this DLL (I use `version.dll` DLL hijacking), you can use the following [ScyllaHide](https://github.com/x64dbg/ScyllaHide) options to debug Wibu CodeMeter:

![ScyllaHide](https://i.imgur.com/EevkEor.png)

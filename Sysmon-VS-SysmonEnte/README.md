# Steps to reproduce the experiments

System Setup:
* Windows 11 development VM provided by Microsoft running on VirtualBox
* Using Sysmon v14.0 and a generic "log-all" configuration
* Using evtxdump (source available in https://github.com/0xrawsec/golang-etw)

## Lab Preparation

1. install Sysmon `.\Sysmon.exe -accepteula -i sysmon.xml`
2. verify Sysmon config is good `sysmon.exe -c`
3. verify that you can receive Sysmon events with etwdump `.\etwdump.exe -stats "Microsoft-Windows-Sysmon"`
4. start some applications and look at the logs Sysmon generates. You should see quite a lot since we log everything.

Once we have done that, our environment is ready for testing

## Running SysmonEnte and collecting its trace

1. If you are running your experiments in a VM, make a snapshot so that you can easily revert back in case of mistake
2. Disable any AV feature. This is a precaution otherwise you might fail at running EntenLoader.exe
2. Run etwdump to dump the events it collects to a file: `.\etwdump.exe -o .\SysmonEnte-trace.json "Microsoft-Windows-Sysmon"`
3. Run as an Administrator EntenLoader.exe (inside SysmonEnte.zip) -> this is a version I compiled myself, if you want you are free to use your own.
4. At this point, if EntenLoader.exe worked you should see a success message. If it failed, make sure you are executing it with Administrator privileges.
4. Wait a bit and hit **Ctrl+C** on etwdump console
5. You get a nice trace files with JSON encoded events, use the tool you like to analyse it :)

NB: in order to verify that EnteLoader worked, you should search for **ProcessAccess** events with a **CallTrace** equal to **Ente**. You can find an example below:

```json
{
  "Event": {
    "EventData": {
      "CallTrace": "Ente",
      "GrantedAccess": "0x1400",
      "RuleName": "-",
      "SourceImage": "C:\\Windows\\system32\\taskmgr.exe",
      "SourceProcessGUID": "{0bd59c11-4e04-6318-3c02-000000000e00}",
      "SourceProcessId": "6636",
      "SourceThreadId": "3792",
      "SourceUser": "Ente",
      "TargetImage": "C:\\Windows\\system32\\lsass.exe",
      "TargetProcessGUID": "{0bd59c11-c4ed-6318-0c00-000000000e00}",
      "TargetProcessId": "692",
      "TargetUser": "NT AUTHORITY\\SYSTEM",
      "UtcTime": "2022-09-07 08:43:20.742"
    },
    "System": {
      "Channel": "Microsoft-Windows-Sysmon/Operational",
      "Computer": "WinDev2204Eval",
      [...]
    }
  }
}

```

## Collecting Baseline events

1. Enable an ETW autologger (not mandatory but it is better if you don't want to loose events generated at boot)
    1.1 create autologger `.\etwdump.exe -autologger SysmonLabTrace "Microsoft-Windows-Sysmon"`
    1.2 verify the autologger has been created: `reg query HKLM\System\CurrentControlSet\Control\WMI\Autologger\SysmonLabTrace`
    1.3 reboot the machine to make the autologger starting
2. Reboot the System so that WMI autologger starts logging in the trace you've just created
3. Collect events from trace `.\etwdump.exe -o sysmon-baseline.json -a "SysmonLabTrace"` for a relevant period of time. You can interact with the system in order to generate some activity



##hiii

| Rule Name | Description  | Author |   OS_Product_Platform  | MITRE Attack Techniques | Log Source | Rule Content |
| ----------- | ----------- | ---------- | ---------- | ----------  | ---------- | ---------- |
| Console History  | Checks for execution of Console History  | Mohammad Ghanbari  | Windows  | 0  | sysmon  | EventID=1 ( CommandLine="*Get-History*" OR CommandLine="*AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt*"  OR  CommandLine="*(Get-PSReadlineOption).HistorySavePath*" )   |
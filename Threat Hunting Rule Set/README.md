##Mitre Attack

| Rule Name | Description  | Author |   OS_Product_Platform  | MITRE Attack Techniques | Log Source | Rule Content |
| ----------- | ----------- | ---------- | ---------- | ----------  | ---------- | ---------- |

| Console History  | Checks for execution of Console History  | Mohammad Ghanbari  | Windows  |   | sysmon  | EventID=1 ( CommandLine="*Get-History*" OR CommandLine="*AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt*"  OR  CommandLine="*(Get-PSReadlineOption).HistorySavePath*") |

| Named Pipes | Checks for  Named Pipes	| Mohammad Ghanbari	| Windows |  | sysmon | EventID=17 pipe_name IN ( "\\isapi_http*","\\isapi_dg*" ,"\\isapi_dg2*" ,"\\isapi_http*" , "\\sdlrpc*" ,"\\aheec*" ,"\\winsession*" ,"\\lsassw*","\\rpchlp_3*"  ,"\\NamePipe_MoreWindows*" ,"\\pcheap_reuse*" , "\\PSEXESVC*" ,"\\PowerShellISEPipeName_*"  ,"\\csexec*"  , "\\paexec*" ,"\\remcom*") |

| Named Pipes - CobaltStrike | Checks for  Named Pipes |	Mohammad Ghanbari |	Windows	| | sysmon	| EventID=17 pipe_name="\\msagent_*" |

| Remotely Query Login Sessions - Network | Checks for execution of Remotely Query Login Sessions | Mohammad Ghanbari | Windows	| |sysmon | EventID=3 Image="*\\qwinsta.exe" OR Process="qwinsta.exe" | 

| Suspicious filename used | Checks for execution of Suspicious filename | Mohammad Ghanbari |Windows | | sysmon | EventID=1 Image IN ("*\\a.exe" , "*\\b.exe" , "*\\c.exe" , "*\\d.exe" , "*\\e.exe" , "*\\f.exe" ,"*\\g.exe" , "*\\h.exe" , "*\\i.exe" ,"*\\j.exe" ,"*\\k.exe","*\\l.exe" ,"*\\m.exe" ,"*\\n.exe" ,"*\\o.exe" ,"*\\p.exe" ,"*\\q.exe" ,"*\\r.exe" ,"*\\s.exe" ,"*\\t.exe" ,"*\\u.exe" ,"*\\v.exe" ,"*\\w.exe" ,"*\\x.exe" ,"*\\y.exe" ,"*\\z.exe" ,"*\\1.exe" ,"*\\2.exe" ,"*\\3.exe" ,"*\\4.exe" ,"*\\5.exe" ,"*\\6.exe" ,"*\\7.exe" ,"*\\8.exe" ,"*\\9.exe" , "*\\0.exe" ,"*\\10.exe") OR Process IN ( "a.exe" , "b.exe" , "c.exe" , "d.exe" , "e.exe" , "f.exe" ,"g.exe" , "h.exe",  "i.exe" ,"j.exe" ,"k.exe","l.exe" ,"m.exe" ,"n.exe" ,"o.exe" ,"p.exe" ,"q.exe" ,"r.exe" ,"s.exe" ,"t.exe" ,"u.exe" ,"v.exe" ,"w.exe" ,"x.exe" ,"y.exe" ,"z.exe" ,"1.exe" ,"2.exe" ,"3.exe" ,"4.exe" ,"5.exe" ,"6.exe" ,"7.exe" ,"8.exe" ,"9.exe" , "0.exe" ,"10.exe") | 



Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
currentDir = fso.GetParentFolderName(WScript.ScriptFullName)

exePath = currentDir & "\dist\VibeAudit.exe"
If Not fso.FileExists(exePath) Then
    exePath = currentDir & "\VibeAudit.exe"
End If

If fso.FileExists(exePath) Then
    WshShell.Run """" & exePath & """", 0, False
Else
    WshShell.Run "cmd /c """ & currentDir & "\Lancer_Vibe_Audit.bat""", 1, False
End If

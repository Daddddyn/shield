; Shield installer (Inno Setup 6.x). build.ps1 compiles this after PyInstaller has produced dist\Shield.
;
; Installs for the current Windows user only (no administrator prompt). That is deliberate: it is what lets the
; in-app "Install and restart" update run silently without a UAC dialog every time.
;
; NEVER change AppId. Windows uses it to recognise "the same app", which is how a new installer upgrades the old
; copy in place instead of installing a second one.

#ifndef AppVersion
  #define AppVersion "2.2.0"
#endif
#ifndef AppVersion4
  #define AppVersion4 "2.2.0.0"
#endif
#define AppName "Shield"
#define AppExe "Shield.exe"
#define AppPublisher "Shield"

[Setup]
AppId={{1BAB4729-C97D-438C-8604-F32627BB9052}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion4}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} Setup
PrivilegesRequired=lowest
DefaultDirName={autopf}\{#AppName}
UsePreviousAppDir=yes
DisableProgramGroupPage=yes
DisableDirPage=yes
DisableReadyPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\release
OutputBaseFilename=Shield-Setup-{#AppVersion}
SetupIconFile=shield.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupMutex=ShieldBrowserSetupMutex
CloseApplications=yes
CloseApplicationsFilter={#AppExe}
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; Flags: unchecked

[InstallDelete]
; Start from a clean program folder every time, so nothing from an older build lingers next to the new files.
; (Your settings, history and vault live in your user folder, not here, and are never touched.)
Type: filesandordirs; Name: "{app}\_internal"
Type: files; Name: "{app}\{#AppExe}"

[Files]
Source: "..\dist\Shield\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; AppUserModelID: "Shield.Browser"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; AppUserModelID: "Shield.Browser"; Tasks: desktopicon

[Registry]
; Makes Shield appear under Settings > Apps > Default apps, and lets it open links and .html files.
; Everything is under HKEY_CURRENT_USER and is removed again on uninstall. Windows does not let any program make
; itself the default browser; the person picks it on the Default apps page.
Root: HKCU; Subkey: "Software\Classes\ShieldHTML"; ValueType: string; ValueName: ""; ValueData: "Shield HTML Document"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\ShieldHTML\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExe},0"
Root: HKCU; Subkey: "Software\Classes\ShieldHTML\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" ""%1"""
Root: HKCU; Subkey: "Software\Classes\ShieldURL"; ValueType: string; ValueName: ""; ValueData: "Shield URL"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\ShieldURL"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKCU; Subkey: "Software\Classes\ShieldURL\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExe},0"
Root: HKCU; Subkey: "Software\Classes\ShieldURL\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"" ""%1"""
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Shield"; ValueType: string; ValueName: ""; ValueData: "{#AppName}"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Shield\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExe},0"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Shield\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExe}"""
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Shield\Capabilities"; ValueType: string; ValueName: "ApplicationName"; ValueData: "{#AppName}"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Shield\Capabilities"; ValueType: string; ValueName: "ApplicationDescription"; ValueData: "A zero-bloat, security-first browser"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Shield\Capabilities"; ValueType: string; ValueName: "ApplicationIcon"; ValueData: "{app}\{#AppExe},0"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Shield\Capabilities\URLAssociations"; ValueType: string; ValueName: "http"; ValueData: "ShieldURL"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Shield\Capabilities\URLAssociations"; ValueType: string; ValueName: "https"; ValueData: "ShieldURL"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Shield\Capabilities\FileAssociations"; ValueType: string; ValueName: ".htm"; ValueData: "ShieldHTML"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Shield\Capabilities\FileAssociations"; ValueType: string; ValueName: ".html"; ValueData: "ShieldHTML"
Root: HKCU; Subkey: "Software\RegisteredApplications"; ValueType: string; ValueName: "Shield"; ValueData: "Software\Clients\StartMenuInternet\Shield\Capabilities"; Flags: uninsdeletevalue

[Run]
; Fresh install: offer to open Shield, and to open the Default apps page.
Filename: "{app}\{#AppExe}"; Description: "Open Shield"; Flags: nowait postinstall skipifsilent
Filename: "ms-settings:defaultapps"; Description: "Choose Shield as my default browser"; Flags: shellexec nowait postinstall skipifsilent unchecked
; Update started from inside Shield (silent): bring Shield back when the new files are in place.
Filename: "{app}\{#AppExe}"; Flags: nowait; Check: RelaunchRequested

[UninstallDelete]
Type: filesandordirs; Name: "{app}\_internal"

[Code]
function RelaunchRequested: Boolean;
begin
  Result := ExpandConstant('{param:RELAUNCH|0}') = '1';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and (not UninstallSilent) then
    if MsgBox('Also delete your Shield data (settings, history, downloads log and the password vault)?' + #13#10 + #13#10 +
              'This cannot be undone. Choose No to keep it for a future install.',
              mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(ExpandConstant('{%USERPROFILE}\.shieldbrowser'), True, True, True);
end;

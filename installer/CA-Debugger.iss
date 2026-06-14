; CA Debugger — Inno Setup 6 installer
; A standalone source-level debugger addin for the Clarion IDE (10 / 11 / 12).
; The user picks which Clarion version(s) to install into; paths are auto-detected.
;
; Build with installer\build-installer.ps1 (it stages the per-version addin builds
; + the engine, then invokes ISCC on this script). Do not run ISCC directly unless
; the staging\ folders have already been populated.

#define MyAppName "CA Debugger"
#define MyAppVersion "1.0.1"
#define MyAppPublisher "ClarionLive"
#define MyAppURL "https://github.com/ClarionLive/CA-Debugger"

; Source staging directories (populated by build-installer.ps1).
; Paths are relative to this .iss file (the installer\ folder).
#define SrcStage "staging"
#define SrcC10 SrcStage + "\C10"
#define SrcC11 SrcStage + "\C11"
#define SrcC12 SrcStage + "\C12"
#define SrcEngine SrcStage + "\engine"
#define SrcDocs "..\docs"

[Setup]
AppId={{66D0C904-4298-4649-A4F3-D5F503464B27}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
DefaultDirName={autopf}\CA Debugger
DisableDirPage=yes
DisableProgramGroupPage=yes
OutputDir=output
OutputBaseFilename=CA-Debugger-{#MyAppVersion}-Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x86compatible
UsedUserAreasWarning=no
LicenseFile=LICENSE.txt
InfoBeforeFile=PREINSTALL.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Types]
Name: "full"; Description: "Full installation"
Name: "custom"; Description: "Custom installation"; Flags: iscustom

; ============================================================
; COMPONENTS — Clarion version selection
; ============================================================

[Components]
Name: "clarion12"; Description: "Clarion 12 Addin"; Types: full custom
Name: "clarion11"; Description: "Clarion 11 Addin"; Types: full custom
Name: "clarion10"; Description: "Clarion 10 Addin"; Types: full custom
Name: "docs"; Description: "User Guide"; Types: full custom

; ============================================================
; FILES
; ============================================================

[Files]
; --- Clarion 12 Addin ---
Source: "{#SrcC12}\ClarionDebugger.dll"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcC12}\ClarionDebugger.pdb"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcC12}\ClarionDebugger.addin"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcC12}\Microsoft.Web.WebView2.Core.dll"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcC12}\Microsoft.Web.WebView2.WinForms.dll"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcC12}\Microsoft.Web.WebView2.Wpf.dll"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcC12}\WebView2Loader.dll"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcC12}\runtimes\win-x86\native\WebView2Loader.dll"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger\runtimes\win-x86\native"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcC12}\Terminal\debugger.html"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger\Terminal"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.exe"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.Core.dll"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.pdb"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.Core.pdb"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion
Source: "{#SrcEngine}\Iced.dll"; DestDir: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12; Flags: ignoreversion

; --- Clarion 11 Addin ---
Source: "{#SrcC11}\ClarionDebugger.dll"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcC11}\ClarionDebugger.pdb"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcC11}\ClarionDebugger.addin"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcC11}\Microsoft.Web.WebView2.Core.dll"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcC11}\Microsoft.Web.WebView2.WinForms.dll"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcC11}\Microsoft.Web.WebView2.Wpf.dll"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcC11}\WebView2Loader.dll"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcC11}\runtimes\win-x86\native\WebView2Loader.dll"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger\runtimes\win-x86\native"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcC11}\Terminal\debugger.html"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger\Terminal"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.exe"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.Core.dll"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.pdb"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.Core.pdb"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion
Source: "{#SrcEngine}\Iced.dll"; DestDir: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11; Flags: ignoreversion

; --- Clarion 10 Addin ---
Source: "{#SrcC10}\ClarionDebugger.dll"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcC10}\ClarionDebugger.pdb"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcC10}\ClarionDebugger.addin"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcC10}\Microsoft.Web.WebView2.Core.dll"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcC10}\Microsoft.Web.WebView2.WinForms.dll"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcC10}\Microsoft.Web.WebView2.Wpf.dll"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcC10}\WebView2Loader.dll"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcC10}\runtimes\win-x86\native\WebView2Loader.dll"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger\runtimes\win-x86\native"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcC10}\Terminal\debugger.html"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger\Terminal"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.exe"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.Core.dll"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.pdb"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcEngine}\ClarionDbg.Core.pdb"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion
Source: "{#SrcEngine}\Iced.dll"; DestDir: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10; Flags: ignoreversion

; --- User Guide (shared) ---
Source: "{#SrcDocs}\user-guide.html"; DestDir: "{app}"; Components: docs; Flags: ignoreversion

; ============================================================
; POST-INSTALL
; ============================================================

[Run]
Filename: "{app}\user-guide.html"; \
  Description: "View the User Guide"; \
  Components: docs; \
  Flags: nowait postinstall skipifsilent shellexec unchecked

[UninstallDelete]
Type: filesandordirs; Name: "{code:GetC12Path}\accessory\addins\ClarionDebugger"; Components: clarion12
Type: filesandordirs; Name: "{code:GetC11Path}\accessory\addins\ClarionDebugger"; Components: clarion11
Type: filesandordirs; Name: "{code:GetC10Path}\accessory\addins\ClarionDebugger"; Components: clarion10

; ============================================================
; PASCAL SCRIPT — Clarion path detection, validation, cleanup
; ============================================================

[Code]
var
  C10Path, C11Path, C12Path: string;
  ClarionPathPage: TInputQueryWizardPage;
  BrowseBtn0, BrowseBtn1, BrowseBtn2: TNewButton;

function GetC10Path(Param: string): string; begin Result := C10Path; end;
function GetC11Path(Param: string): string; begin Result := C11Path; end;
function GetC12Path(Param: string): string; begin Result := C12Path; end;

// Auto-detect Clarion install roots from the registry, then common folders.
procedure DetectClarionPaths;
var
  Path: string;
begin
  C12Path := '';
  if RegQueryStringValue(HKLM32, 'SOFTWARE\SoftVelocity\Clarion12', 'root', Path) and DirExists(Path) then
    C12Path := Path
  else if DirExists('C:\Clarion12') then C12Path := 'C:\Clarion12'
  else if DirExists('C:\Clarion12d') then C12Path := 'C:\Clarion12d';

  C11Path := '';
  if RegQueryStringValue(HKLM32, 'SOFTWARE\SoftVelocity\Clarion11.1', 'root', Path) and DirExists(Path) then
    C11Path := Path
  else if RegQueryStringValue(HKLM32, 'SOFTWARE\SoftVelocity\Clarion11', 'root', Path) and DirExists(Path) then
    C11Path := Path
  else if DirExists('C:\Clarion11') then C11Path := 'C:\Clarion11'
  else if DirExists('C:\Clarion11-13372') then C11Path := 'C:\Clarion11-13372';

  C10Path := '';
  if RegQueryStringValue(HKLM32, 'SOFTWARE\SoftVelocity\Clarion10', 'root', Path) and DirExists(Path) then
    C10Path := Path
  else if DirExists('C:\Clarion10') then C10Path := 'C:\Clarion10'
  else if DirExists('C:\Clarion10v8') then C10Path := 'C:\Clarion10v8';
end;

// The debugger pad is hosted in a WebView2 control — the runtime is required.
function IsWebView2Installed: Boolean;
var
  Version: string;
begin
  Result := RegQueryStringValue(HKLM32, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version);
  if not Result then
    Result := RegQueryStringValue(HKLM, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version);
end;

procedure BrowseForPath(EditIndex: Integer);
var
  Dir: string;
begin
  Dir := ClarionPathPage.Values[EditIndex];
  if Dir = '' then Dir := 'C:\';
  if BrowseForFolder('Select Clarion installation folder:', Dir, False) then
    ClarionPathPage.Values[EditIndex] := Dir;
end;

procedure BrowseBtn0Click(Sender: TObject); begin BrowseForPath(0); end;
procedure BrowseBtn1Click(Sender: TObject); begin BrowseForPath(1); end;
procedure BrowseBtn2Click(Sender: TObject); begin BrowseForPath(2); end;

procedure AddBrowseButton(var Btn: TNewButton; EditIndex, EditWidth: Integer; Handler: TNotifyEvent);
begin
  Btn := TNewButton.Create(WizardForm);
  Btn.Parent := ClarionPathPage.Edits[EditIndex].Parent;
  Btn.Caption := 'Browse...';
  Btn.Left := ClarionPathPage.Edits[EditIndex].Left + EditWidth + 6;
  Btn.Top := ClarionPathPage.Edits[EditIndex].Top;
  Btn.Width := 75;
  Btn.Height := ClarionPathPage.Edits[EditIndex].Height;
  Btn.OnClick := Handler;
  ClarionPathPage.Edits[EditIndex].Width := EditWidth;
end;

procedure InitializeWizard;
var
  DetectedMsg: string;
  EditWidth: Integer;
begin
  DetectClarionPaths;

  DetectedMsg := 'Select the Clarion installation folders.' + #13#10#13#10 +
    'Auto-detected paths are shown below. Edit any path that is incorrect,' + #13#10 +
    'or leave a field empty to skip that version.';

  ClarionPathPage := CreateInputQueryPage(wpLicense,
    'Clarion Installation Paths',
    'Where are your Clarion versions installed?',
    DetectedMsg);

  ClarionPathPage.Add('Clarion 12 folder:', False);
  ClarionPathPage.Add('Clarion 11 folder:', False);
  ClarionPathPage.Add('Clarion 10 folder:', False);

  EditWidth := ClarionPathPage.Edits[0].Width - 85;
  AddBrowseButton(BrowseBtn0, 0, EditWidth, @BrowseBtn0Click);
  AddBrowseButton(BrowseBtn1, 1, EditWidth, @BrowseBtn1Click);
  AddBrowseButton(BrowseBtn2, 2, EditWidth, @BrowseBtn2Click);

  ClarionPathPage.Values[0] := C12Path;
  ClarionPathPage.Values[1] := C11Path;
  ClarionPathPage.Values[2] := C10Path;
end;

function ValidateClarionPath(const Caption, Path: string): Boolean;
begin
  Result := True;
  if Path = '' then Exit;
  if not DirExists(Path + '\bin') then
  begin
    MsgBox(Caption + ' path does not appear valid (no "bin" directory):' + #13#10 + Path + #13#10#13#10 +
           'Leave the field empty to skip this version, or correct the path.', mbError, MB_OK);
    Result := False;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;

  if CurPageID = ClarionPathPage.ID then
  begin
    C12Path := ClarionPathPage.Values[0];
    C11Path := ClarionPathPage.Values[1];
    C10Path := ClarionPathPage.Values[2];

    if not ValidateClarionPath('Clarion 12', C12Path) then begin Result := False; Exit; end;
    if not ValidateClarionPath('Clarion 11', C11Path) then begin Result := False; Exit; end;
    if not ValidateClarionPath('Clarion 10', C10Path) then begin Result := False; Exit; end;

    if (C12Path = '') and (C11Path = '') and (C10Path = '') then
    begin
      MsgBox('At least one Clarion version path is required.' + #13#10 +
             'Please enter the path to your Clarion installation.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;

  if CurPageID = wpSelectComponents then
  begin
    if WizardIsComponentSelected('clarion12') and (C12Path = '') then
    begin
      MsgBox('Clarion 12 addin is selected but no Clarion 12 path was specified.' + #13#10 +
             'Go back and enter the path, or uncheck Clarion 12.', mbError, MB_OK);
      Result := False; Exit;
    end;
    if WizardIsComponentSelected('clarion11') and (C11Path = '') then
    begin
      MsgBox('Clarion 11 addin is selected but no Clarion 11 path was specified.' + #13#10 +
             'Go back and enter the path, or uncheck Clarion 11.', mbError, MB_OK);
      Result := False; Exit;
    end;
    if WizardIsComponentSelected('clarion10') and (C10Path = '') then
    begin
      MsgBox('Clarion 10 addin is selected but no Clarion 10 path was specified.' + #13#10 +
             'Go back and enter the path, or uncheck Clarion 10.', mbError, MB_OK);
      Result := False; Exit;
    end;
  end;
end;

function InitializeSetup: Boolean;
var
  Msg: string;
begin
  Result := True;

  if not IsWebView2Installed then
  begin
    Msg := 'Microsoft Edge WebView2 Runtime was not detected.' + #13#10 +
           'The debugger pad needs it to display its UI.' + #13#10#13#10 +
           'Download from:' + #13#10 +
           '  https://developer.microsoft.com/en-us/microsoft-edge/webview2/' + #13#10#13#10 +
           'You can continue, but the pad will be blank until WebView2 is installed.' + #13#10#13#10 +
           'Continue anyway?';
    Result := (MsgBox(Msg, mbConfirmation, MB_YESNO) = IDYES);
  end;
end;

// Auto-check the version components that have a detected path; disable the rest.
procedure CurPageChanged(CurPageID: Integer);
var
  i: Integer;
  Cap: string;
  HasPath: Boolean;
begin
  if CurPageID = wpSelectComponents then
  begin
    for i := 0 to WizardForm.ComponentsList.Items.Count - 1 do
    begin
      Cap := WizardForm.ComponentsList.ItemCaption[i];
      HasPath := True;
      if Cap = 'Clarion 12 Addin' then HasPath := (C12Path <> '') and DirExists(C12Path)
      else if Cap = 'Clarion 11 Addin' then HasPath := (C11Path <> '') and DirExists(C11Path)
      else if Cap = 'Clarion 10 Addin' then HasPath := (C10Path <> '') and DirExists(C10Path)
      else Continue;
      WizardForm.ComponentsList.Checked[i] := HasPath;
      WizardForm.ComponentsList.ItemEnabled[i] := HasPath;
    end;
  end;
end;

// Remove a previous install of the addin for each selected version before copying.
procedure RemovePrevious(const Path: string);
begin
  if (Path <> '') and DirExists(Path + '\accessory\addins\ClarionDebugger') then
  begin
    Log('Removing previous addin: ' + Path);
    DelTree(Path + '\accessory\addins\ClarionDebugger', True, True, True);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  NeedsRestart := False;
  if WizardIsComponentSelected('clarion12') then RemovePrevious(C12Path);
  if WizardIsComponentSelected('clarion11') then RemovePrevious(C11Path);
  if WizardIsComponentSelected('clarion10') then RemovePrevious(C10Path);
end;

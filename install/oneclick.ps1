#Requires -Version 5.1
param([string]$Owner="mkkoerner42-cpu",[string]$Repo="nemesis2")
$ErrorActionPreference='Stop'
$Base=Split-Path -Parent $MyInvocation.MyCommand.Path
$Log="$Base\install.log"
if(!(Test-Path $Base)){New-Item -ItemType Directory -Path $Base|Out-Null}
if(!(Test-Path $Log)){New-Item -ItemType File -Path $Log|Out-Null}
$logCmd="`"Write-Host '*** NEMESIS2 INSTALL LOG ***';Write-Host 'Datei: $Log';'';Get-Content -Path '$Log' -Wait -Tail 50`""
Start-Process -FilePath "powershell" -ArgumentList "-NoLogo","-NoExit","-Command",$logCmd|Out-Null
function Log($m){$ts=Get-Date -Format "yyyy-MM-dd HH:mm:ss";Add-Content -Path $Log -Value "[$ts] $m";Write-Host $m}
function Need($name,$cmd){if(!(Get-Command $cmd -ErrorAction SilentlyContinue)){Log "Fehlt: $name ($cmd)";throw "$name fehlt"}else{Log "OK: $name ($cmd)"}}
Log "Start für $Owner/$Repo"
Need "Git" "git"
Need "GitHub CLI" "gh"
Write-Host "GitHub PAT eingeben (wird NICHT geloggt):"
$pat=Read-Host -AsSecureString
$B=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($pat);$GH=[Runtime.InteropServices.Marshal]::PtrToStringAuto($B);[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($B)|Out-Null
Write-Host "OPENAI_API_KEY eingeben (wird NICHT geloggt):"
$oa=Read-Host -AsSecureString
$B2=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($oa);$OPENAI=[Runtime.InteropServices.Marshal]::PtrToStringAuto($B2);[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($B2)|Out-Null
if([string]::IsNullOrWhiteSpace($GH) -or [string]::IsNullOrWhiteSpace($OPENAI)){Log "Abbruch: leere Eingaben";exit 1}
Log "gh auth login…"
$psi=New-Object Diagnostics.ProcessStartInfo
$psi.FileName="gh";$psi.Arguments="auth login --with-token"
$psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true;$psi.UseShellExecute=$false
$p=New-Object Diagnostics.Process;$p.StartInfo=$psi;$p.Start()|Out-Null
$p.StandardInput.WriteLine($GH);$p.StandardInput.Close()
$stdout=$p.StandardOutput.ReadToEnd();$stderr=$p.StandardError.ReadToEnd();$p.WaitForExit()
Log "gh stdout: $stdout"; if($p.ExitCode -ne 0){Log "gh stderr: $stderr";throw "gh login fehlgeschlagen"}
function Set-Secret($n,$v){$tmp=[IO.Path]::GetTempFileName();Set-Content -Path $tmp -Value $v -NoNewline;try{Log "Setze Secret $n …"; & cmd /c "gh secret set $n -R $Owner/$Repo < `"$tmp`"" 2>&1|%{Log $_}}finally{Remove-Item $tmp -Force -ErrorAction SilentlyContinue}}
Set-Secret "OPENAI_API_KEY" $OPENAI
Set-Secret "GH_TOKEN" $GH
try{Log "Trigger Workflow agent-lite.yml"; gh workflow run "agent-lite.yml" -R "$Owner/$Repo" 2>&1|%{Log $_}}catch{Log "Hinweis: Workflow evtl. noch nicht gepusht: $($_.Exception.Message)"}
Log "Fertig. Actions-Tab prüfen. Logfenster bleibt offen."

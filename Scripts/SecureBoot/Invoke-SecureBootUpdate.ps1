<#
.SYNOPSIS
    Prüft und aktualisiert die Windows UEFI Secure Boot 2023 Zertifikate.
.DESCRIPTION
    Hauptskript zur Analyse und Aktualisierung der Secure Boot Zertifikate.
    Prüft db, KEK, Boot-Manager-Signatur, BitLocker-Schutz und triggert
    bei Bedarf das Microsoft Zertifikats-Update.

    Referenz: KB5062710 - Windows Secure Boot certificate expiration and CA updates
    https://support.microsoft.com/topic/5062710

    Benötigte Zertifikate (Ablauf 2026):
    - Windows UEFI CA 2023              (db)  - Boot Loader Signatur
    - Microsoft Corporation KEK 2K CA 2023 (KEK) - DB/DBX Updates
    - Microsoft UEFI CA 2023             (db)  - 3rd-Party Boot Loader
    - Microsoft Option ROM UEFI CA 2023  (db)  - Option ROMs
.NOTES
    Erfordert Administratorrechte.
    Bei aktivem BitLocker wird der Schutz automatisch pausiert.
.EXAMPLE
    .\Invoke-SecureBootUpdate.ps1 -Info
    Zeigt eine vollstaendige Systemanalyse (Zertifikate, BitLocker, Readiness).
.EXAMPLE
    .\Invoke-SecureBootUpdate.ps1 -ApplyUpdate
    Prueft und fuehrt fehlende Zertifikats-Updates durch.
.EXAMPLE
    .\Invoke-SecureBootUpdate.ps1 -Check
    Schnell-Nachkontrolle: Prueft ob die 2023-Zertifikate nach dem Update vorhanden sind.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [switch]$Info,

    [Parameter()]
    [switch]$ApplyUpdate,

    [Parameter()]
    [switch]$Check
)

function Write-SectionHeader {
    <#
    .SYNOPSIS
        Gibt eine formatierte Abschnittsüberschrift auf der Konsole aus.
    .DESCRIPTION
        Erzeugt eine visuell abgesetzte Überschrift mit Rahmen für strukturierte Konsolenausgaben.
    .PARAMETER Title
        Der anzuzeigende Titel.
    .EXAMPLE
        Write-SectionHeader -Title 'Secure Boot Status'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Title
    )

    $line = '=' * 60
    Write-Host ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-StatusLine {
    <#
    .SYNOPSIS
        Gibt eine farbige Statuszeile (OK/FEHLER) auf der Konsole aus.
    .DESCRIPTION
        Zeigt einen Prüfpunkt mit farbigem Status an. Grün bei Erfolg, Rot bei Fehler.
    .PARAMETER Label
        Beschreibung des Prüfpunkts.
    .PARAMETER Status
        Boolean-Wert: $true = OK, $false = FEHLER.
    .PARAMETER DisplayValue
        Optionaler Anzeigewert statt OK/FEHLER.
    .EXAMPLE
        Write-StatusLine -Label 'Windows UEFI CA 2023' -Status $true
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter(Mandatory)]
        [bool]$Status,

        [Parameter()]
        [string]$DisplayValue
    )

    $color = if ($Status) { 'Green' } else { 'Red' }
    $icon = if ($Status) { '[OK]' } else { '[FEHLER]' }
    $value = if ($DisplayValue) { $DisplayValue } else { $icon }

    Write-Host ("  {0,-45} : {1}" -f $Label, $value) -ForegroundColor $color
}

function Write-InfoLine {
    <#
    .SYNOPSIS
        Gibt eine neutrale Informationszeile auf der Konsole aus.
    .PARAMETER Label
        Beschreibung.
    .PARAMETER Value
        Anzeigewert.
    .EXAMPLE
        Write-InfoLine -Label 'Hostname' -Value $env:COMPUTERNAME
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Label,

        [Parameter(Mandatory)]
        [string]$Value
    )

    Write-Host ("  {0,-45} : {1}" -f $Label, $Value) -ForegroundColor White
}

function Write-ActionMessage {
    <#
    .SYNOPSIS
        Gibt eine Aktionsmeldung auf der Konsole aus.
    .PARAMETER Message
        Die Meldung.
    .PARAMETER Type
        Typ: Info, Warning, Success, Error.
    .EXAMPLE
        Write-ActionMessage -Message 'BitLocker wird pausiert...' -Type Warning
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Success', 'Error')]
        [string]$Type = 'Info'
    )

    $colorMap = @{
        Info    = 'White'
        Warning = 'Yellow'
        Success = 'Green'
        Error   = 'Red'
    }
    $iconMap = @{
        Info    = '[i]'
        Warning = '[!]'
        Success = '[+]'
        Error   = '[X]'
    }

    Write-Host "  $($iconMap[$Type]) $Message" -ForegroundColor $colorMap[$Type]
}

function Write-SummaryTable {
    <#
    .SYNOPSIS
        Gibt eine Zusammenfassung aller Prüfpunkte als Tabelle aus.
    .PARAMETER Results
        Array von Hashtables mit Name und Status.
    .EXAMPLE
        Write-SummaryTable -Results @(@{Name='Test';Status=$true})
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Results
    )

    Write-SectionHeader -Title 'Zusammenfassung'

    $passed = ($Results | Where-Object { $_.Status -eq $true }).Count
    $failed = ($Results | Where-Object { $_.Status -eq $false }).Count

    foreach ($result in $Results) {
        Write-StatusLine -Label $result.Name -Status $result.Status
    }

    Write-Host ''
    Write-Host ("  Bestanden: {0}  |  Fehlgeschlagen: {1}  |  Gesamt: {2}" -f $passed, $failed, $Results.Count) -ForegroundColor $(if ($failed -eq 0) { 'Green' } else { 'Yellow' })
    Write-Host ''
}




function Test-SecureBootEnabled {
    <#
    .SYNOPSIS
        Prüft ob Secure Boot auf dem System aktiviert ist.
    .DESCRIPTION
        Nutzt Confirm-SecureBootUEFI um den Secure-Boot-Status abzufragen.
    .OUTPUTS
        [bool] $true wenn Secure Boot aktiv, sonst $false.
    .EXAMPLE
        Test-SecureBootEnabled
    #>
    [CmdletBinding()]
    param()

    try {
        $state = Microsoft.PowerShell.Management\Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction Stop
        if ($null -ne $state.UEFISecureBootEnabled) {
            return ([int]$state.UEFISecureBootEnabled) -eq 1
        }
    }
    catch {
        Write-Verbose "Secure-Boot-Registrystatus konnte nicht gelesen werden: $_"
    }

    try {
        $result = Confirm-SecureBootUEFI -ErrorAction Stop
        return [bool]$result
    }
    catch {
        Write-Verbose "Secure Boot konnte nicht abgefragt werden: $_"
        return $false
    }
}

function Get-FirmwareModeInfo {
    [CmdletBinding()]
    param()

    try {
        $computerInfo = Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop
        $biosFirmwareType = [string]$computerInfo.BiosFirmwareType
        switch -Regex ($biosFirmwareType) {
            '^Uefi$' {
                return [PSCustomObject]@{
                    FirmwareType    = 'UEFI'
                    IsUefi          = $true
                    DetectionSource = 'Get-ComputerInfo: BiosFirmwareType'
                }
            }
            '^Legacy$' {
                return [PSCustomObject]@{
                    FirmwareType    = 'BIOS/Legacy'
                    IsUefi          = $false
                    DetectionSource = 'Get-ComputerInfo: BiosFirmwareType'
                }
            }
        }
    }
    catch {
        Write-Verbose "Firmware-Modus konnte per Get-ComputerInfo nicht gelesen werden: $_"
    }

    try {
        $control = Microsoft.PowerShell.Management\Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction Stop
        switch ([int]$control.PEFirmwareType) {
            1 {
                return [PSCustomObject]@{
                    FirmwareType    = 'BIOS/Legacy'
                    IsUefi          = $false
                    DetectionSource = 'Registry: PEFirmwareType'
                }
            }
            2 {
                return [PSCustomObject]@{
                    FirmwareType    = 'UEFI'
                    IsUefi          = $true
                    DetectionSource = 'Registry: PEFirmwareType'
                }
            }
        }
    }
    catch {
        Write-Verbose "Firmware-Modus konnte per Registry nicht gelesen werden: $_"
    }

    return [PSCustomObject]@{
        FirmwareType    = 'Unbekannt'
        IsUefi          = $false
        DetectionSource = 'Keine verlässliche Firmwarequelle verfügbar'
    }
}

function Get-SecureBootCertificateStatus {
    <#
    .SYNOPSIS
        Prüft die UEFI-Signaturdatenbanken (db, KEK) auf benötigte 2023-Zertifikate.
    .OUTPUTS
        [PSCustomObject[]] Array mit Zertifikatname, Speicherort und Gefunden-Status.
    #>
    [CmdletBinding()]
    param()

    $certificates = @(
        @{ Name = 'Windows UEFI CA 2023';                  Store = 'db';  SearchIn = 'db'  }
        @{ Name = 'Microsoft Corporation KEK 2K CA 2023';   Store = 'KEK'; SearchIn = 'kek' }
        @{ Name = 'Microsoft UEFI CA 2023';                 Store = 'db';  SearchIn = 'db'  }
        @{ Name = 'Microsoft Option ROM UEFI CA 2023';      Store = 'db';  SearchIn = 'db'  }
        @{ Name = 'Windows Production PCA 2011';            Store = 'db';  SearchIn = 'db'  }
        @{ Name = 'Microsoft Corporation UEFI CA 2011';     Store = 'db';  SearchIn = 'db'  }
        @{ Name = 'Microsoft Corporation KEK CA 2011';      Store = 'KEK'; SearchIn = 'kek' }
    )

    $dbBytes  = $null
    $kekBytes = $null

    try {
        $dbBytes = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name db -ErrorAction Stop).bytes)
    }
    catch {
        Write-Warning "Signaturdatenbank (db) konnte nicht gelesen werden: $_"
    }

    try {
        $kekBytes = [System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI -Name kek -ErrorAction Stop).bytes)
    }
    catch {
        Write-Warning "Key Exchange Key (KEK) konnte nicht gelesen werden: $_"
    }

    $results = foreach ($cert in $certificates) {
        $source = if ($cert.SearchIn -eq 'db') { $dbBytes } else { $kekBytes }
        $found  = if ($source) { $source -match [regex]::Escape($cert.Name) } else { $false }

        [PSCustomObject]@{
            Name    = $cert.Name
            Store   = $cert.Store
            Found   = [bool]$found
            Is2023  = $cert.Name -match '2023'
        }
    }

    return $results
}

#region Webhook-Funktion
function Send-SecureBootWebhook {
    <#
    .SYNOPSIS
        Sendet Telemetrie-Daten an den zentralen Webhook.
    .DESCRIPTION
        Zentrale Funktion für alle Webhook-Aufrufe im Secure Boot Modul.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Daten,

        [string]$Url = "https://cim.d1ng2.net/api/empfang",
        [string]$Token = "MIB-GMBH-757"
    )

    $headers = @{
        "Authorization" = "Bearer757 $Token"
        "Content-Type"  = "application/json"
    }

    try {
        $jsonBody = $Daten | ConvertTo-Json -Depth 10

        $response = Invoke-RestMethod -Uri $Url `
                                    -Method Post `
                                    -Body $jsonBody `
                                    -Headers $headers `
                                    -TimeoutSec 5
        if ($response) {
            $response | ConvertTo-Json -Depth 3 | Out-Null
        }
    }
    catch {
        
        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $reader.BaseStream.Position = 0    
            } catch {}
        }
    }
}
#endregion


function Get-SecureBootPlatformStatus {
    <#
    .SYNOPSIS
        Ermittelt Firmware-Typ und Secure-Boot-Status des Systems.
    .OUTPUTS
        [PSCustomObject] mit FirmwareType, IsUefi, IsSupported, IsEnabled und Message.
    #>
    [CmdletBinding()]
    param()

    $firmwareInfo = Get-FirmwareModeInfo
    $firmwareType = $firmwareInfo.FirmwareType
    $isUefi = $firmwareInfo.IsUefi

    if (-not $isUefi) {
        return [PSCustomObject]@{
            FirmwareType    = $firmwareType
            IsUefi          = $false
            IsSupported     = $false
            IsEnabled       = $false
            DetectionSource = $firmwareInfo.DetectionSource
            Message         = 'System wurde nicht im UEFI-Modus gestartet. Secure-Boot-Zertifikate koennen auf BIOS-/Legacy-Systemen nicht verwaltet werden.'
        }
    }

    # Helper-Funktion für Webhook-Aufruf
    function Send-StatusWebhook {
        param([string]$StatusMessage)
        
        $daten = @{
            section     = "Secure Boot Zertifikats-Pruefung"
            computer    = $env:COMPUTERNAME
            benutzer    = "$env:USERDOMAIN\$env:USERNAME"
            datum       = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'
            windowsVersion = [System.Environment]::OSVersion.VersionString
            mainboardHersteller = if ($boardInfo) { $boardInfo.Hersteller } else { 'n/a' }
            mainboardModell     = if ($boardInfo) { $boardInfo.Modell } else { 'n/a' }
            biosVersion         = if ($boardInfo) { $boardInfo.BiosVersion } else { 'n/a' }
            biosDatum           = if ($boardInfo) { $boardInfo.BiosDatum } else { 'n/a' }
            logDatei            = if ($logPath) { $logPath } else { 'n/a' }
            status              = $StatusMessage
            seriennummer        = if ($systemInfo) { $systemInfo.SerialNumber } else { 'n/a' }
            biosSeriennummer    = if ($biosInfo) { $biosInfo.SerialNumber } else { 'n/a' }
            uuid                = if ($systemInfo) { $systemInfo.UUID } else { 'n/a' }
        }
        Send-SecureBootWebhook -Daten $daten
    }

    try {
        $state = Microsoft.PowerShell.Management\Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name UEFISecureBootEnabled -ErrorAction Stop
        
        if ($null -ne $state.UEFISecureBootEnabled) {
            $isEnabled = ([int]$state.UEFISecureBootEnabled) -eq 1
            
            if (-not $isEnabled) {
                Send-StatusWebhook -StatusMessage 'Secure Boot ist im UEFI vorhanden, aber aktuell deaktiviert.'
            }
            
            return [PSCustomObject]@{
                FirmwareType    = $firmwareType
                IsUefi          = $true
                IsSupported     = $true
                IsEnabled       = $isEnabled
                DetectionSource = 'Registry: UEFISecureBootEnabled'
                Message         = if ($isEnabled) { 
                                    'Secure Boot ist aktiviert.' 
                                  } else { 
                                    'Secure Boot ist im UEFI vorhanden, aber aktuell deaktiviert.' 
                                  }
            }
        }
    }
    catch {
        Write-Verbose "Secure-Boot-Registrystatus konnte nicht gelesen werden: $_"
    }

    try {
        $result = Confirm-SecureBootUEFI -ErrorAction Stop
        $isEnabled = [bool]$result

        if (-not $isEnabled) {
            Send-StatusWebhook -StatusMessage 'Secure Boot ist im UEFI vorhanden, aber aktuell deaktiviert.'
        }

        return [PSCustomObject]@{
            FirmwareType    = $firmwareType
            IsUefi          = $true
            IsSupported     = $true
            IsEnabled       = $isEnabled
            DetectionSource = 'Cmdlet: Confirm-SecureBootUEFI'
            Message         = if ($isEnabled) { 
                                'Secure Boot ist aktiviert.' 
                              } else { 
                                'Secure Boot ist im UEFI vorhanden, aber aktuell deaktiviert.' 
                              }
        }
    }
    catch {
        $errorText = $_.Exception.Message
        $isDisabled = $errorText -match 'not enabled|deaktiviert|nicht aktiviert'
        $isAccessDenied = $errorText -match 'Zugriff verweigert|Access is denied|SetPrivilegeFailed'

        $statusMessage = if ($isDisabled) {
            'Secure Boot ist im UEFI vorhanden, aber aktuell deaktiviert.'
        }
        elseif ($isAccessDenied) {
            'Secure-Boot-Status konnte wegen fehlender Firmware-Berechtigungen nicht direkt abgefragt werden.'
        }
        else {
            "Secure-Boot-Status konnte nicht eindeutig abgefragt werden: $errorText"
        }

        Send-StatusWebhook -StatusMessage $statusMessage

        return [PSCustomObject]@{
            FirmwareType    = $firmwareType
            IsUefi          = $true
            IsSupported     = $true
            IsEnabled       = $false
            DetectionSource = 'Fehler/Fallback: Confirm-SecureBootUEFI'
            Message         = $statusMessage
        }
    }
}

function Get-SecureBootReadiness {
    <#
    .SYNOPSIS
        Liest den 2023Capable-Registrywert aus um die Update-Bereitschaft zu prüfen.
    .DESCRIPTION
        Wert 0 = nicht bereit, 1 = teilweise bereit, 2 = vollständig bereit.
    .OUTPUTS
        [PSCustomObject] mit CapableValue und IsReady.
    .EXAMPLE
        Get-SecureBootReadiness
    #>
    [CmdletBinding()]
    param()

    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'

    try {
        $state = Get-ItemProperty -Path $regPath -ErrorAction Stop
        $capable = if ($state.PSObject.Properties.Name -contains '2023Capable') {
            $state.'2023Capable'
        }
        else { 0 }
    }
    catch {
        Write-Warning "Registry-Pfad konnte nicht gelesen werden: $_"
        $capable = 0
    }

    return [PSCustomObject]@{
        CapableValue = $capable
        IsReady      = ($capable -eq 2)
    }
}

function Get-BootManagerSignature {
    <#
    .SYNOPSIS
        Prüft ob der Windows Boot Manager mit dem neuen 2023-Zertifikat signiert ist.
    .DESCRIPTION
        Liest die Signatur des Boot-Managers über den EFI-Systempfad aus.
    .OUTPUTS
        [PSCustomObject] mit SignedWith2023-Status.
    .EXAMPLE
        Get-BootManagerSignature
    #>
    [CmdletBinding()]
    param()

    $signed2023 = $false

    try {
        $efiPath = "$env:SystemDrive\EFI\Microsoft\Boot\bootmgfw.efi"

        if (-not (Test-Path -Path $efiPath)) {
            [void](mountvol S: /S 2>&1)
            $efiPath = 'S:\EFI\Microsoft\Boot\bootmgfw.efi'
        }

        if (Test-Path -Path $efiPath) {
            $signature = Get-AuthenticodeSignature -FilePath $efiPath -ErrorAction Stop
            $signed2023 = $signature.SignerCertificate.Subject -match '2023'
        }
    }
    catch {
        Write-Verbose "Boot-Manager-Signatur konnte nicht geprüft werden: $_"
    }

    return [PSCustomObject]@{
        Path          = $efiPath
        SignedWith2023 = $signed2023
    }
}

function Start-SecureBootCertificateUpdate {
    <#
    .SYNOPSIS
        Triggert das Secure Boot Zertifikats-Update über den Scheduled Task.
    .DESCRIPTION
        Setzt den Registry-Wert AvailableUpdates auf 0x5944 und startet
        den Microsoft Scheduled Task 'Secure-Boot-Update'.
        Gemäß KB5025885 (Schritt 1) installiert 0x5944 die 2023-Secure-Boot-Zertifikate
        in DB und KEK sowie den 2023-signierten Boot Manager in einem Schritt.
        (Früher war 0x100 ein separater Schritt für den Boot Manager allein;
        dieser wurde von Microsoft im April 2026 aus der Anleitung entfernt.)
    .OUTPUTS
        [PSCustomObject] mit Erfolgsstatus.
    .EXAMPLE
        Start-SecureBootCertificateUpdate
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param()

    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'

    if (-not $PSCmdlet.ShouldProcess('SecureBoot AvailableUpdates', 'Registry-Wert auf 0x5944 setzen und Update-Task starten')) {
        return [PSCustomObject]@{ UpdateTriggered = $false; Reason = 'Abgebrochen' }
    }

    try {
        Set-ItemProperty -Path $regPath -Name 'AvailableUpdates' -Value 0x5944 -Force -ErrorAction Stop
        Start-ScheduledTask -TaskName '\Microsoft\Windows\PI\Secure-Boot-Update' -ErrorAction Stop

        return [PSCustomObject]@{ UpdateTriggered = $true; Reason = 'Erfolgreich gestartet' }
    }
    catch {
        Write-Warning "Secure Boot Update konnte nicht gestartet werden: $_"
        return [PSCustomObject]@{ UpdateTriggered = $false; Reason = $_.Exception.Message }
    }
}

function ConvertFrom-EfiSignatureList {
    # Interner Helfer – nicht exportiert.
    # Parst das UEFI EFI Signature List Format und gibt strukturierte Objekte zurück.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$Bytes,

        [Parameter(Mandatory)]
        [string]$VariableName
    )

    $knownGuids = @{
        'a5c059a1-94e4-4aa7-87b5-ab155c2bf072' = 'X509'
        'c1c41626-504c-4092-aca9-41f936934328' = 'SHA256'
        '3c5766e8-269c-4e34-aa14-ed776e85b3b6' = 'RSA2048'
    }

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $offset  = 0

    while ($offset + 28 -le $Bytes.Length) {
        # EFI_SIGNATURE_LIST Header: GUID (16) + ListSize (4) + HeaderSize (4) + SignatureSize (4)
        $guidBytes  = $Bytes[$offset..($offset + 15)]
        $guid       = [System.Guid]::new([byte[]]$guidBytes).ToString().ToLower()
        $offset    += 16

        if ($offset + 12 -gt $Bytes.Length) { break }

        $listSize   = [System.BitConverter]::ToUInt32($Bytes, $offset); $offset += 4
        $headerSize = [System.BitConverter]::ToUInt32($Bytes, $offset); $offset += 4
        $sigSize    = [System.BitConverter]::ToUInt32($Bytes, $offset); $offset += 4

        $offset    += [int]$headerSize   # Header-Daten überspringen

        $certType    = if ($knownGuids.ContainsKey($guid)) { $knownGuids[$guid] } else { 'Unbekannt' }
        $sigDataSize = [int]$listSize - 28 - [int]$headerSize

        if ($sigSize -gt 16 -and $sigDataSize -gt 0) {
            $sigCount = [int]($sigDataSize / [int]$sigSize)

            for ($i = 0; $i -lt $sigCount; $i++) {
                if ($offset + [int]$sigSize -gt $Bytes.Length) { break }

                # Jeder Eintrag: 16 Bytes Owner-GUID + eigentliche Signaturdaten
                $offset      += 16

                $certDataSize = [int]$sigSize - 16
                $certData     = $Bytes[$offset..($offset + $certDataSize - 1)]
                $offset      += $certDataSize

                if ($certType -eq 'X509') {
                    try {
                        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$certData)
                        $cn   = if ($cert.Subject -match 'CN=([^,]+)') { $Matches[1].Trim() } else { $cert.Subject }

                        $results.Add([PSCustomObject]@{
                            Variable   = $VariableName
                            Typ        = 'X509'
                            CommonName = $cn
                            Subject    = $cert.Subject
                            Issuer     = $cert.Issuer
                            Thumbprint = $cert.Thumbprint
                            NotBefore  = $cert.NotBefore
                            NotAfter   = $cert.NotAfter
                        })
                    }
                    catch {
                        Write-Verbose "Zertifikat-Eintrag konnte nicht geparst werden: $_"
                    }
                }
                elseif ($certType -eq 'SHA256') {
                    $hash = [System.BitConverter]::ToString($certData) -replace '-', ''
                    $results.Add([PSCustomObject]@{
                        Variable   = $VariableName
                        Typ        = 'SHA256'
                        CommonName = "SHA256:$($hash.Substring(0, [Math]::Min(16, $hash.Length)))…"
                        Subject    = "Hash: $hash"
                        Issuer     = 'n/a'
                        Thumbprint = $hash
                        NotBefore  = $null
                        NotAfter   = $null
                    })
                }
            }
        }
        else {
            $offset += [Math]::Max(0, $sigDataSize)
        }
    }

    return $results.ToArray()
}

function Get-SecureBootDatabaseSources {
    <#
    .SYNOPSIS
        Liest UEFI Secure Boot Datenbanken und ermittelt die Herkunft jedes Eintrags.
    .DESCRIPTION
        Vergleicht die aktiven UEFI-Signaturdatenbanken (db, KEK) mit den
        Werks-Defaults (dbDefault, KEKDefault). Dadurch lässt sich erkennen,
        welche Zertifikate ab Werk im BIOS/UEFI hinterlegt sind und welche
        nachträglich durch Windows oder das Betriebssystem hinzugefügt wurden.
    .OUTPUTS
        [PSCustomObject[]] Array mit Name, Datenbank, Typ, Herkunft, Thumbprint,
        Aussteller und Gültigkeitsdatum.
    .EXAMPLE
        Get-SecureBootDatabaseSources
    #>
    [CmdletBinding()]
    param()

    $databases = @(
        @{ Active = 'db';  Default = 'dbDefault';  Label = 'db'  }
        @{ Active = 'kek'; Default = 'KEKDefault';  Label = 'KEK' }
    )

    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($dbEntry in $databases) {
        $activeBytes  = $null
        $defaultBytes = $null

        try {
            $activeBytes  = (Get-SecureBootUEFI -Name $dbEntry.Active  -ErrorAction Stop).bytes
        }
        catch {
            Write-Warning "Datenbank '$($dbEntry.Active)' konnte nicht gelesen werden: $_"
        }

        try {
            $defaultBytes = (Get-SecureBootUEFI -Name $dbEntry.Default -ErrorAction Stop).bytes
        }
        catch {
            Write-Verbose "Werks-Default '$($dbEntry.Default)' nicht verfügbar (bei manchen OEMs normal): $_"
        }

        # Thumbprints aus den Werks-Defaults indexieren
        $defaultThumbprints = @{}
        if ($defaultBytes) {
            foreach ($dc in (ConvertFrom-EfiSignatureList -Bytes $defaultBytes -VariableName $dbEntry.Default)) {
                $defaultThumbprints[$dc.Thumbprint] = $true
            }
        }

        # Aktive Datenbank parsen und Herkunft bestimmen
        if ($activeBytes) {
            foreach ($ac in (ConvertFrom-EfiSignatureList -Bytes $activeBytes -VariableName $dbEntry.Label)) {
                # Nur Microsoft-relevante Eintraege behalten
                if ($ac.CommonName -notmatch 'Microsoft|Windows') { continue }

                $herkunft = if ($defaultBytes -and $defaultThumbprints.ContainsKey($ac.Thumbprint)) {
                    'BIOS/OEM'
                }
                elseif (-not $defaultBytes) {
                    'Unbekannt'
                }
                else {
                    'Windows/OS'
                }

                $gueltigBis = if ($ac.NotAfter) {
                    $ac.NotAfter.ToString('dd.MM.yyyy')
                }
                else { 'n/a' }

                $allResults.Add([PSCustomObject]@{
                    Datenbank  = $ac.Variable
                    Typ        = $ac.Typ
                    Name       = $ac.CommonName
                    Herkunft   = $herkunft
                    Thumbprint = $ac.Thumbprint
                    Aussteller = $ac.Issuer
                    GueltigBis = $gueltigBis
                })
            }
        }
    }

    return $allResults.ToArray()
}

function Get-BoardInfo {
    <#
    .SYNOPSIS
        Liest Mainboard- und BIOS-Informationen via WMI aus.
    .OUTPUTS
        [PSCustomObject] mit Hersteller, Modell, BiosVersion und BiosDatum.
    .EXAMPLE
        Get-BoardInfo
    #>
    [CmdletBinding()]
    param()

    try {
        function Format-BoardInfoValue {
            param(
                [Parameter()]
                [AllowNull()]
                [string]$Value,

                [Parameter(Mandatory)]
                [string]$Fallback
            )

            if ([string]::IsNullOrWhiteSpace($Value)) {
                return $Fallback
            }

            return $Value.Trim()
        }

        $board = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop
        $bios  = Get-CimInstance -ClassName Win32_BIOS     -ErrorAction Stop

        $biosDate = if ($bios.ReleaseDate) {
            $bios.ReleaseDate.ToString('dd.MM.yyyy')
        }
        else { 'unbekannt' }

        return [PSCustomObject]@{
            Hersteller  = Format-BoardInfoValue -Value $board.Manufacturer -Fallback 'unbekannt'
            Modell      = Format-BoardInfoValue -Value $board.Product -Fallback 'unbekannt'
            BiosVersion = Format-BoardInfoValue -Value $bios.SMBIOSBIOSVersion -Fallback 'unbekannt'
            BiosDatum   = $biosDate
        }
    }
    catch {
        Write-Warning "Board-/BIOS-Informationen konnten nicht gelesen werden: $_"
        return [PSCustomObject]@{
            Hersteller  = 'n/a'
            Modell      = 'n/a'
            BiosVersion = 'n/a'
            BiosDatum   = 'n/a'
        }
    }
}

function Test-AdminPrivileges {
    <#
    .SYNOPSIS
        Prüft ob das Skript mit Administratorrechten ausgeführt wird.
    .OUTPUTS
        [bool] $true wenn Administrator, sonst $false.
    .EXAMPLE
        Test-AdminPrivileges
    #>
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


function Get-BitLockerProtectionStatus {
    <#
    .SYNOPSIS
        Prüft den BitLocker-Schutzstatus aller Laufwerke.
    .DESCRIPTION
        Gibt für jedes Laufwerk den Verschlüsselungs- und Schutzstatus zurück.
        Fokus liegt auf dem Systemlaufwerk (typisch C:).
    .OUTPUTS
        [PSCustomObject[]] Array mit MountPoint, ProtectionStatus, VolumeStatus.
    .EXAMPLE
        Get-BitLockerProtectionStatus
    #>
    [CmdletBinding()]
    param()

    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop

        $results = foreach ($vol in $volumes) {
            [PSCustomObject]@{
                MountPoint       = $vol.MountPoint
                ProtectionStatus = $vol.ProtectionStatus.ToString()
                VolumeStatus     = $vol.VolumeStatus.ToString()
                IsProtected      = ($vol.ProtectionStatus -eq 'On')
                IsSystemDrive    = ($vol.MountPoint -eq "$env:SystemDrive\")
            }
        }

        return $results
    }
    catch {
        Write-Warning "BitLocker-Status konnte nicht ermittelt werden: $_"
        return @()
    }
}

function Suspend-BitLockerForUpdate {
    <#
    .SYNOPSIS
        Pausiert den BitLocker-Schutz auf dem Systemlaufwerk für Secure Boot Updates.
    .DESCRIPTION
        Setzt den BitLocker-Schutz für eine definierte Anzahl Neustarts aus.
        Standard: 2 Neustarts (empfohlen für Secure Boot Zertifikats-Updates).
        Bei RebootCount 0 wird der Schutz bis zum manuellen Fortsetzen pausiert.
    .PARAMETER MountPoint
        Laufwerksbuchstabe (Standard: Systemlaufwerk).
    .PARAMETER RebootCount
        Anzahl erlaubter Neustarts ohne BitLocker-Schutz (Standard: 2).
    .OUTPUTS
        [PSCustomObject] mit Erfolgsstatus.
    .EXAMPLE
        Suspend-BitLockerForUpdate
    .EXAMPLE
        Suspend-BitLockerForUpdate -MountPoint 'D:' -RebootCount 3
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter()]
        [string]$MountPoint = "$env:SystemDrive",

        [Parameter()]
        [ValidateRange(0, 15)]
        [int]$RebootCount = 2
    )

    if (-not $PSCmdlet.ShouldProcess($MountPoint, "BitLocker-Schutz fuer $RebootCount Neustart(s) pausieren")) {
        return [PSCustomObject]@{ Suspended = $false; MountPoint = $MountPoint; Reason = 'Abgebrochen' }
    }

    try {
        Suspend-BitLocker -MountPoint $MountPoint -RebootCount $RebootCount -ErrorAction Stop

        return [PSCustomObject]@{
            Suspended   = $true
            MountPoint  = $MountPoint
            RebootCount = $RebootCount
            Reason      = 'Erfolgreich pausiert'
        }
    }
    catch {
        Write-Warning "BitLocker konnte nicht pausiert werden: $_"
        return [PSCustomObject]@{ Suspended = $false; MountPoint = $MountPoint; Reason = $_.Exception.Message }
    }
}

function Resume-BitLockerAfterUpdate {
    <#
    .SYNOPSIS
        Setzt den BitLocker-Schutz auf dem angegebenen Laufwerk fort.
    .PARAMETER MountPoint
        Laufwerksbuchstabe (Standard: Systemlaufwerk).
    .OUTPUTS
        [PSCustomObject] mit Erfolgsstatus.
    .EXAMPLE
        Resume-BitLockerAfterUpdate
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter()]
        [string]$MountPoint = "$env:SystemDrive"
    )

    if (-not $PSCmdlet.ShouldProcess($MountPoint, 'BitLocker-Schutz fortsetzen')) {
        return [PSCustomObject]@{ Resumed = $false; MountPoint = $MountPoint }
    }

    try {
        Resume-BitLocker -MountPoint $MountPoint -ErrorAction Stop
        return [PSCustomObject]@{ Resumed = $true; MountPoint = $MountPoint }
    }
    catch {
        Write-Warning "BitLocker konnte nicht fortgesetzt werden: $_"
        return [PSCustomObject]@{ Resumed = $false; MountPoint = $MountPoint }
    }
}

#endregion

#region Administratorprüfung
if (-not (Test-AdminPrivileges)) {
    Write-ActionMessage -Message 'Dieses Skript erfordert Administratorrechte. Bitte als Administrator ausfuehren.' -Type Error
    exit 1
}
#endregion

#region Parameterpruefung
if (-not ($Info -or $ApplyUpdate -or $Check)) {
    Write-Host ''
    Write-Host '  Fehler: Kein Modus angegeben.' -ForegroundColor Red
    Write-Host ''
    Write-Host '  Verwendung:' -ForegroundColor Yellow
    Write-Host '    -Info         Vollstaendige Systemanalyse anzeigen' -ForegroundColor Yellow
    Write-Host '    -ApplyUpdate  Fehlende Zertifikate aktualisieren' -ForegroundColor Yellow
    Write-Host '    -Check        Schnell-Nachkontrolle nach dem Update' -ForegroundColor Yellow
    exit 1
}
if (($Info.IsPresent -as [int]) + ($ApplyUpdate.IsPresent -as [int]) + ($Check.IsPresent -as [int]) -gt 1) {
    Write-Host ''
    Write-Host '  Fehler: Nur einen Modus gleichzeitig angeben (-Info, -ApplyUpdate oder -Check).' -ForegroundColor Red
    exit 1
}
#endregion

#region Logging
$modeName = if ($Info) { 'Info' } elseif ($ApplyUpdate) { 'ApplyUpdate' } else { 'Check' }
$boardInfo = Get-BoardInfo
$logName   = ($boardInfo.Modell + '_' + $boardInfo.BiosVersion) -replace '[\\/:*?"<>|]', '_'
$logPath   = Join-Path $PSScriptRoot ("{0}-{1}.log" -f $logName, $modeName)
$systemInfo = Get-CimInstance -ClassName Win32_ComputerSystemProduct -ErrorAction SilentlyContinue
$biosInfo   = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue

Start-Transcript -Path $logPath -Force | Out-Null
#endregion

try {

#region Schnell-Nachkontrolle (-Check)
if ($Check) {
    Write-SectionHeader -Title 'Schnell-Nachkontrolle: 2023-Zertifikate'
    $certCheck = Get-SecureBootCertificateStatus
    $only2023  = $certCheck | Where-Object { $_.Is2023 }
    foreach ($c in $only2023) {
        $label = '{0} ({1})' -f $c.Name, $c.Store
        Write-StatusLine -Label $label -Status $c.Found
    }
    $stillMissing = $only2023 | Where-Object { -not $_.Found }
    if (($stillMissing | Measure-Object).Count -eq 0) {
        Write-ActionMessage -Message 'Alle 2023-Zertifikate sind vorhanden. Update war erfolgreich.' -Type Success
        $daten = @{
            section     = "Secure Boot Zertifikats-Pruefung"
            computer    = $env:COMPUTERNAME
            benutzer    = "$env:USERDOMAIN\$env:USERNAME"
            datum       = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'
            windowsVersion = [System.Environment]::OSVersion.VersionString
            mainboardHersteller = $boardInfo.Hersteller
            mainboardModell     = $boardInfo.Modell
            biosVersion         = $boardInfo.BiosVersion
            biosDatum           = $boardInfo.BiosDatum
            logDatei            = $logPath
            status              = "Erfolgreich:Alle_2023_Zertifiakte_vorhanden"
            seriennummer        = $systemInfo.SerialNumber
            biosSeriennummer    = $biosInfo.SerialNumber
            uuid                = $systemInfo.UUID
        }
        Send-SecureBootWebhook -Daten $daten
        }
        else {
        Write-ActionMessage -Message 'Es fehlen noch 2023-Zertifikate. Ggf. ist ein Neustart erforderlich.' -Type Warning
        foreach ($m in $stillMissing) {
            Write-ActionMessage -Message "Fehlt: $($m.Name) ($($m.Store))" -Type Warning
        }
    }
    exit 0
}
#endregion

#region Systeminfo-Header
Write-SectionHeader -Title 'Secure Boot Zertifikats-Pruefung'
Write-InfoLine -Label 'Computer' -Value $env:COMPUTERNAME
Write-InfoLine -Label 'Benutzer' -Value "$env:USERDOMAIN\$env:USERNAME"
Write-InfoLine -Label 'Datum' -Value (Get-Date -Format 'dd.MM.yyyy HH:mm:ss')
Write-InfoLine -Label 'Windows-Version' -Value ([System.Environment]::OSVersion.VersionString)
Write-InfoLine -Label 'Mainboard Hersteller' -Value $boardInfo.Hersteller
Write-InfoLine -Label 'Mainboard Modell' -Value $boardInfo.Modell
Write-InfoLine -Label 'BIOS Version' -Value $boardInfo.BiosVersion
Write-InfoLine -Label 'BIOS Datum' -Value $boardInfo.BiosDatum
Write-InfoLine -Label 'Log-Datei' -Value $logPath
#endregion

#region Secure Boot Status
Write-SectionHeader -Title 'Secure Boot Grundstatus'

$platformStatus = Get-SecureBootPlatformStatus
Write-InfoLine -Label 'Firmware-Modus' -Value $platformStatus.FirmwareType
Write-InfoLine -Label 'Secure-Boot-Quelle' -Value $platformStatus.DetectionSource
Write-StatusLine -Label 'Secure Boot aktiviert' -Status $platformStatus.IsEnabled

if (-not $platformStatus.IsSupported) {
    Write-ActionMessage -Message $platformStatus.Message -Type Error
    Write-ActionMessage -Message 'Bitte das System im UEFI-Modus starten. Auf BIOS-/Legacy-Installationen ist dieses Paket nicht einsetzbar.' -Type Warning
    $daten = @{
        section     = "Secure Boot Zertifikats-Pruefung"
        computer    = $env:COMPUTERNAME
        benutzer    = "$env:USERDOMAIN\$env:USERNAME"
        datum       = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'
        windowsVersion = [System.Environment]::OSVersion.VersionString
        mainboardHersteller = $boardInfo.Hersteller
        mainboardModell     = $boardInfo.Modell
        biosVersion         = $boardInfo.BiosVersion
        biosDatum           = $boardInfo.BiosDatum
        logDatei            = $logPath
        status              = "Fehler:Legacy_BIOS_Mode"
        seriennummer        = $systemInfo.SerialNumber
        biosSeriennummer    = $biosInfo.SerialNumber
        uuid                = $systemInfo.UUID
    }
    Send-SecureBootWebhook -Daten $daten
    exit 1
}

if (-not $platformStatus.IsEnabled) {
    Write-ActionMessage -Message $platformStatus.Message -Type Error
    Write-ActionMessage -Message 'Bitte Secure Boot im UEFI/BIOS aktivieren und das Skript danach erneut starten.' -Type Warning
    $daten = @{
        section     = "Secure Boot Zertifikats-Pruefung"
        computer    = $env:COMPUTERNAME
        benutzer    = "$env:USERDOMAIN\$env:USERNAME"
        datum       = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'
        windowsVersion = [System.Environment]::OSVersion.VersionString
        mainboardHersteller = $boardInfo.Hersteller
        mainboardModell     = $boardInfo.Modell
        biosVersion         = $boardInfo.BiosVersion
        biosDatum           = $boardInfo.BiosDatum
        logDatei            = $logPath
        status              = "Fehler:Secure_Boot_deaktiviert."
        seriennummer        = $systemInfo.SerialNumber
        biosSeriennummer    = $biosInfo.SerialNumber
        uuid                = $systemInfo.UUID
    }
    Send-SecureBootWebhook -Daten $daten
    exit 1
}
#endregion

#region Zertifikate prüfen
Write-SectionHeader -Title 'Zertifikate in UEFI-Datenbanken'

$certStatus = Get-SecureBootCertificateStatus
$summaryResults = @()

foreach ($cert in $certStatus) {
    $label = "{0} ({1})" -f $cert.Name, $cert.Store
    Write-StatusLine -Label $label -Status $cert.Found
    $summaryResults += @{ Name = $cert.Name; Status = $cert.Found }
}

$missing2023 = $certStatus | Where-Object { $_.Is2023 -and -not $_.Found }
$has2023Issues = ($missing2023 | Measure-Object).Count -gt 0
#endregion

#region Zertifikatsherkunft: BIOS/OEM vs. Windows/OS
Write-SectionHeader -Title 'Zertifikatsherkunft: BIOS/OEM vs. Windows/OS'

$dbSources    = Get-SecureBootDatabaseSources
$biosCerts    = @($dbSources | Where-Object { $_.Herkunft -eq 'BIOS/OEM' })
$osCerts      = @($dbSources | Where-Object { $_.Herkunft -eq 'Windows/OS' })
$unknownCerts = @($dbSources | Where-Object { $_.Herkunft -eq 'Unbekannt' })

if ($dbSources.Count -eq 0) {
    Write-ActionMessage -Message 'Keine Zertifikatsdaten verfuegbar (kein Secure Boot oder kein Admin-Zugriff).' -Type Warning
}
else {
    # --- BIOS/OEM ---
    Write-Host ''
    Write-Host "  Im BIOS/UEFI ab Werk hinterlegt  ($($biosCerts.Count) Eintraege):" -ForegroundColor Cyan

    if ($biosCerts.Count -gt 0) {
        foreach ($cert in $biosCerts) {
            $display = '[{0}]  {1}' -f $cert.Datenbank, $cert.Name
            Write-Host ('  {0,-52} gueltig bis {1}' -f $display, $cert.GueltigBis) -ForegroundColor Cyan
        }
    }
    else {
        Write-Host '    (keine oder dbDefault nicht verfuegbar)' -ForegroundColor DarkGray
    }

    # --- Windows / OS ---
    Write-Host ''
    Write-Host "  Durch Windows / Betriebssystem hinzugefuegt  ($($osCerts.Count) Eintraege):" -ForegroundColor Yellow

    if ($osCerts.Count -gt 0) {
        foreach ($cert in $osCerts) {
            $display = '[{0}]  {1}' -f $cert.Datenbank, $cert.Name
            Write-Host ('  {0,-52} gueltig bis {1}' -f $display, $cert.GueltigBis) -ForegroundColor Yellow
        }
    }
    else {
        Write-Host '    (keine)' -ForegroundColor DarkGray
    }

    # --- Herkunft unbekannt (kein dbDefault vorhanden) ---
    if ($unknownCerts.Count -gt 0) {
        Write-Host ''
        Write-Host "  Herkunft unbekannt (dbDefault nicht lesbar)  ($($unknownCerts.Count) Eintraege):" -ForegroundColor Gray

        foreach ($cert in $unknownCerts) {
            $display = '[{0}]  {1}' -f $cert.Datenbank, $cert.Name
            Write-Host ('  {0,-52} gueltig bis {1}' -f $display, $cert.GueltigBis) -ForegroundColor Gray
        }
    }

    Write-Host ''
    Write-ActionMessage -Message (
        'Gesamt: {0} Eintraege ({1} BIOS/OEM  |  {2} Windows/OS  |  {3} Unbekannt)' -f
        $dbSources.Count, $biosCerts.Count, $osCerts.Count, $unknownCerts.Count
    ) -Type Info
}
#endregion

#region BitLocker Status
Write-SectionHeader -Title 'BitLocker Status'

$bitlockerVolumes = Get-BitLockerProtectionStatus
$systemDriveBL = $bitlockerVolumes | Where-Object { $_.IsSystemDrive }
$bitlockerActive = $false

if ($systemDriveBL) {
    Write-StatusLine -Label "BitLocker Schutz ($($systemDriveBL.MountPoint))" -Status $true -DisplayValue $systemDriveBL.ProtectionStatus
    Write-InfoLine -Label 'Volume-Status' -Value $systemDriveBL.VolumeStatus
    $bitlockerActive = $systemDriveBL.IsProtected
}
else {
    Write-ActionMessage -Message 'BitLocker ist auf dem Systemlaufwerk nicht konfiguriert.' -Type Info
}

foreach ($vol in ($bitlockerVolumes | Where-Object { -not $_.IsSystemDrive })) {
    Write-InfoLine -Label "BitLocker ($($vol.MountPoint))" -Value $vol.ProtectionStatus
}
#endregion

#region Zusammenfassung
Write-SummaryTable -Results $summaryResults
#endregion

#region Aktion: Update durchführen
if ($Info) {
    Write-ActionMessage -Message 'Analyse-Modus (-Info). Fuer das Update mit -ApplyUpdate ausfuehren.' -Type Info
    exit 0
}

if (-not $has2023Issues) {
    Write-ActionMessage -Message 'Alle 2023-Zertifikate sind vorhanden. Kein Update erforderlich.' -Type Success
    $daten = @{
        section     = "Secure Boot Zertifikats-Pruefung"
        computer    = $env:COMPUTERNAME
        benutzer    = "$env:USERDOMAIN\$env:USERNAME"
        datum       = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'
        windowsVersion = [System.Environment]::OSVersion.VersionString
        mainboardHersteller = $boardInfo.Hersteller
        mainboardModell     = $boardInfo.Modell
        biosVersion         = $boardInfo.BiosVersion
        biosDatum           = $boardInfo.BiosDatum
        logDatei            = $logPath
        status              = "Erfolg:Kein_Update_notwendig"
        seriennummer        = $systemInfo.SerialNumber
        biosSeriennummer    = $biosInfo.SerialNumber
        uuid                = $systemInfo.UUID
    }
    Send-SecureBootWebhook -Daten $daten
    exit 0
}

Write-SectionHeader -Title 'Massnahmen zum Zertifikatsupdate'

if ($has2023Issues) {
    Write-ActionMessage -Message 'Fehlende 2023-Zertifikate erkannt. Update wird vorbereitet...' -Type Warning

    foreach ($cert in $missing2023) {
        Write-ActionMessage -Message "Fehlt: $($cert.Name) ($($cert.Store))" -Type Warning
    }
}

#region Lokale Konfiguration fuer Secure Boot
Write-SectionHeader -Title 'Lokale Konfiguration fuer Secure Boot'

$sbRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'

# 1. Registrierungswert fuer die Zertifikatbereitstellung setzen
#    Registrierungswert: AvailableUpdatesPolicy = 22852 (0x5944)
try {
    $cur1 = (Get-ItemProperty -Path $sbRegPath -Name 'AvailableUpdatesPolicy' -ErrorAction SilentlyContinue).AvailableUpdatesPolicy
    if ($cur1 -ne 22852) {
        Set-ItemProperty -Path $sbRegPath -Name 'AvailableUpdatesPolicy' -Value 22852 -Type DWord -Force -ErrorAction Stop
        Write-ActionMessage -Message 'Registrierungswert ''AvailableUpdatesPolicy'': Auf 22852 gesetzt.' -Type Success
    }
    else {
        Write-ActionMessage -Message 'Registrierungswert ''AvailableUpdatesPolicy'': Bereits gesetzt.' -Type Info
    }
}
catch {
    Write-ActionMessage -Message "Registrierungswert 'AvailableUpdatesPolicy': Fehler beim Setzen – $_" -Type Error
}

# 2. Registrierungswert fuer die Update-Bereitstellung setzen
#    Registrierungswert: HighConfidenceOptOut = 1
try {
    $cur2 = (Get-ItemProperty -Path $sbRegPath -Name 'HighConfidenceOptOut' -ErrorAction SilentlyContinue).HighConfidenceOptOut
    if ($cur2 -ne 1) {
        Set-ItemProperty -Path $sbRegPath -Name 'HighConfidenceOptOut' -Value 1 -Type DWord -Force -ErrorAction Stop
        Write-ActionMessage -Message 'Registrierungswert ''HighConfidenceOptOut'': Auf 1 gesetzt.' -Type Success
    }
    else {
        Write-ActionMessage -Message 'Registrierungswert ''HighConfidenceOptOut'': Bereits gesetzt.' -Type Info
    }
}
catch {
    Write-ActionMessage -Message "Registrierungswert 'HighConfidenceOptOut': Fehler beim Setzen – $_" -Type Error
}
#endregion

# BitLocker pausieren falls aktiv
if ($bitlockerActive) {
    Write-ActionMessage -Message 'BitLocker ist aktiv. Schutz wird fuer 2 Neustarts pausiert...' -Type Warning

    $suspendResult = Suspend-BitLockerForUpdate -MountPoint $systemDriveBL.MountPoint -RebootCount 2
    if ($suspendResult.Suspended) {
        Write-ActionMessage -Message 'BitLocker-Schutz erfolgreich pausiert.' -Type Success
    }
    else {
        Write-ActionMessage -Message "BitLocker konnte nicht pausiert werden: $($suspendResult.Reason)" -Type Error
        Write-ActionMessage -Message 'Update wird abgebrochen um BitLocker-Recovery zu vermeiden.' -Type Error
        exit 1
    }
}

# Secure Boot Update triggern
Write-ActionMessage -Message 'Setze Registrierungswert AvailableUpdates = 0x5944...' -Type Info
$updateResult = Start-SecureBootCertificateUpdate

if ($updateResult.UpdateTriggered) {
    Write-ActionMessage -Message 'Secure Boot Update-Task erfolgreich gestartet.' -Type Success
    Write-ActionMessage -Message 'Ein Neustart ist erforderlich um die Zertifikate zu installieren.' -Type Warning
    Write-ActionMessage -Message 'Nach dem Neustart das Skript erneut ausfuehren um den Status zu pruefen.' -Type Info

    Write-Host ''
    Write-ActionMessage -Message 'Neustart wurde verschoben. Bitte manuell neustarten.' -Type Warning
    $daten = @{
        section     = "Secure Boot Zertifikats-Pruefung"
        computer    = $env:COMPUTERNAME
        benutzer    = "$env:USERDOMAIN\$env:USERNAME"
        datum       = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'
        windowsVersion = [System.Environment]::OSVersion.VersionString
        mainboardHersteller = $boardInfo.Hersteller
        mainboardModell     = $boardInfo.Modell
        biosVersion         = $boardInfo.BiosVersion
        biosDatum           = $boardInfo.BiosDatum
        logDatei            = $logPath
        status              = "Erfolg:Update_gestartet-Neustart_erwartet"
        seriennummer        = $systemInfo.SerialNumber
        biosSeriennummer    = $biosInfo.SerialNumber
        uuid                = $systemInfo.UUID
    }
    Send-SecureBootWebhook -Daten $daten









    
}
else {
    Write-ActionMessage -Message "Update konnte nicht gestartet werden: $($updateResult.Reason)" -Type Error
    $daten = @{
        section     = "Secure Boot Zertifikats-Pruefung"
        computer    = $env:COMPUTERNAME
        benutzer    = "$env:USERDOMAIN\$env:USERNAME"
        datum       = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'
        windowsVersion = [System.Environment]::OSVersion.VersionString
        mainboardHersteller = $boardInfo.Hersteller
        mainboardModell     = $boardInfo.Modell
        biosVersion         = $boardInfo.BiosVersion
        biosDatum           = $boardInfo.BiosDatum
        logDatei            = $logPath
        status              = "Fehler:Update_konnte_nicht_gestartet_werden"
        seriennummer        = $systemInfo.SerialNumber
        biosSeriennummer    = $biosInfo.SerialNumber
        uuid                = $systemInfo.UUID
    }
    Send-SecureBootWebhook -Daten $daten
    }
    exit 1
#endregion

} # end try
finally {
    Stop-Transcript | Out-Null

    # Transcript-Meta-Bloecke (Header + Footer) aus der Log-Datei entfernen.
    # Beide Bloecke sind durch Zeilen aus '*'-Zeichen begrenzt.
    if (Test-Path -Path $logPath) {
        $lines   = Get-Content -Path $logPath -Encoding UTF8
        $cleaned = [System.Collections.Generic.List[string]]::new()
        $inBlock = $false

        foreach ($line in $lines) {
            if ($line -match '^\*{4,}') {
                $inBlock = -not $inBlock
                continue
            }
            if (-not $inBlock) {
                $cleaned.Add($line)
            }
        }

        # Fuehrende Leerzeilen entfernen
        $start = 0
        while ($start -lt $cleaned.Count -and [string]::IsNullOrWhiteSpace($cleaned[$start])) { $start++ }

        Set-Content -Path $logPath -Value $cleaned[$start..($cleaned.Count - 1)] -Encoding UTF8
    }
}

# Set-StrictMode -Version latest
$USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36 Edg/89.0.774.68"

Function UrlEncode ($urlToEncode) {
    return [System.Web.HttpUtility]::UrlEncode($urlToEncode)
}
Function UrlDecode ($urlToDecode) {
    return [System.Web.HttpUtility]::UrlDecode($urlToDecode)
}

Function Clear-Globals {
    Write-Verbose "Clearing GLobal Variables"
    if ($fb) { Clear-Variable "fb" -Scope Global }
    if ($fedCredential) { Clear-Variable "fedCredential"  -Scope Global }
}

Function WebPost {
    param (
        [Parameter(Mandatory = $true)] [Uri] $uri,
        [Parameter(Mandatory = $true)] [Object] $body,
        [Parameter(Mandatory = $false)] [Int32] $maxRedirect = 5,
        [Parameter(Mandatory = $false)] $basic = $false,
        [Parameter(Mandatory = $false)] $headers = @{}
    )

    $p = @{
        Uri                = $uri
        Method             = "Post"
        Body               = $body
        MaximumRedirection = $maxRedirect
        ErrorAction        = "Ignore"
        UseBasicParsing    = $basic
        UserAgent          = $USER_AGENT
        Headers            = $headers
    }

    Write-Verbose "[WebPost:Begin]"
    Write-Verbose ($p | ConvertTo-Json)

    Try {
        $Response = Invoke-WebRequest @p -WebSession $global:fb
        Write-Verbose "Response: $($Response.StatusCode) - $($Response.StatusDescription)"
    }
    Catch {
        $Response = ""
        Return
    }
    Write-Verbose "[WebPost:End]"
    Return $Response
}

Function WebGet {
    param (
        [Parameter(Mandatory = $true)] [Uri] $uri,
        [Parameter(Mandatory = $false)] [Int32] $maxRedirect = 5,
        [Parameter(Mandatory = $false)] $basic = $false,
        [Parameter(Mandatory = $false)] $headers = @{}
    )

    $p = @{
        Uri                = $uri
        Method             = "Default"
        MaximumRedirection = $maxRedirect
        ErrorAction        = "Ignore"
        UseBasicParsing    = $basic
        UserAgent          = $USER_AGENT
        Headers            = $headers
    }

    Write-Verbose "[WebGet:Begin]"
    Write-Verbose ($p | ConvertTo-Json)

    $Response = Invoke-WebRequest @p -WebSession $global:fb

    Write-Verbose "WebGet Response: $($Response.StatusCode) - $($Response.StatusDescription)"
    Write-Verbose "[WebGet:End]"

    Return $Response
}

Function Setup-AngleSharp {

    # Load AngleSharp assembly and dependencies

    $myError = $false
    @(
        'AngleSharp'
        'System.Text.Encoding.CodePages',
        'System.Runtime.CompilerServices.Unsafe'
    ) | ForEach-Object {
        $assembly = $_
        try { Add-Type -AssemblyName $_ -ErrorAction Stop }

        catch {

            Try {
                $path = (Get-Package $assembly -ErrorAction Stop).Source
                $path = $path | Split-Path
                Add-Type -Path (Get-ChildItem -Path "$path*\lib\netstandard2.0\*.dll").FullName
            }
            catch {
                $myError = $true
                Write-Warning "Missing $assembly. Please install the package from Nuget..."
                Switch ($assembly) {
                    "AngleSharp" { Write-Output "Install-Package -ProviderName Nuget -SkipDependencies -Name AngleSharp -Scope CurrentUser" }
                    "System.Text.Encoding.CodePages" { Write-Output "Install-Package -ProviderName Nuget -SkipDependencies -Name System.Text.Encoding.CodePages -MaximumVersion 4.5.0 -Scope CurrentUser" }
                    "System.Runtime.CompilerServices.Unsafe" { Write-Output "Install-Package -ProviderName Nuget -skipDependencies -Name System.Runtime.CompilerServices.Unsafe -MaximumVersion 4.5.0 -Scope CurrentUser" }
                }
                Write-Output ""
            }
        }
    }
    if ($myerror) {
        try { $null = Get-PackageSource -Name nuget -ErrorAction Stop }
        catch {
            Write-Warning "Register nuget as a provider..."
            Write-Output "Register-PackageSource -Name NuGet -Location 'https://www.nuget.org/api/v2' -ProviderName NuGet"
        }
        break foobar
    }
}

Function Get-AwsFed {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)] [switch] $clear,
        [Parameter(Mandatory = $false)] [switch] $noDefault
    )
    Begin {
        $ProgressPreference = "SilentlyContinue"
    }
    Process {

        If ($clear.IsPresent) {
            Clear-Globals
            return
        }

        if (-not ($fb)) {
            $global:fb = New-Object -TypeName Microsoft.PowerShell.Commands.WebRequestSession
        }

        if (-not $fedCredential) {
            try {
                $Global:fedCredential = Get-Credential -Message "Enter your federated credential to access AWS"
            }
            catch {
                return
            }
        }
        if (-not $fedCredential) { return }

        Setup-AngleSharp
        $Parser = New-Object AngleSharp.Html.Parser.HtmlParser

        # -- main landing page
        Write-Verbose "Begin ASU aws interface"

        $R = WebGet -uri "https://aws.asu.edu" -basic $true -maxRedirect 10

        If ($R.InputFields[0].name -ne 'SAMLResponse') {

            Write-Verbose "Begin ASU cas weblogin"

            # -- post username and password
            Write-Verbose "Post Username & Password"
            $Parsed = $Parser.ParseDocument($R.Content)
            $form = $Parsed.All | Where-Object ID -EQ 'login'
            $fields = @{}
            $form.elements | Where-Object type -NE 'fieldset' | ForEach-Object { $fields.add( $_.name, $_.value ) }
            $fields["username"] = ($fedCredential.GetNetworkCredential().UserName).ToLower()
            $fields["password"] = $fedCredential.GetNetworkCredential().Password
            $fields["rememberid"] = "true"
            $fields.Remove("submit")

            $headers = @{}
            If (($R.BaseResponse).GetType().Name -eq 'HttpWebResponse') {
                $uri = $R.BaseResponse.ResponseUri
                $uri = $uri.Scheme + "://" + $uri.Host + $uri.LocalPath
            }
            else {
                # HttpsReponseMessage - powershell 6.2+
                $t = $R.BaseResponse.RequestMessage.RequestUri
                $uri = $t.Scheme + "://" + $t.DnsSafeHost + $t.LocalPath
                $headers["Origin"] = $t.Scheme + "://" + $t.DnsSafeHost
                $headers['Referer'] = $t.OriginalString
            }

            $R = WebPost -uri $uri -body $fields -maxRedirect 0 -headers $headers
            Write-Verbose "*********************************"

            If (-not $R -or $R.Forms.Id -eq 'login') {
                Write-Output "User ID and/or Password Incorrect"
                Write-Output $R
                Clear-Globals
                return
            }

            $preDuoCasResponse = $R

            Write-Verbose "Begin Duo Authentication"

            # -- parse sig_request
            $Parsed = $Parser.ParseDocument($R.Content)
            $form = $Parsed.All | Where-Object ID -EQ 'login'
            $e = $form.childnodes | Where-Object id -EQ 'duo_iframe'
            $e = [xml]$e.outerHTML
            $e = $e.iframe
            $sig_request = $e.'data-sig-request'
            Write-Verbose "sig_request: $sig_request"
            $sig_request = $sig_request.split(":")

            $headers = @{}
            # -- get parent
            If (($R.BaseResponse).GetType().Name -eq 'HttpWebResponse') {
                $parent = $R.BaseResponse.ResponseUri.AbsoluteUri
            }
            else {
                # HttpsReponseMessage - powershell 6.2+
                $parent = urlencode $R.BaseResponse.RequestMessage.RequestUri.AbsoluteUri
                $headers['Referer'] = ($R.BaseResponse.RequestMessage.Headers | Where-Object key -EQ 'Origin').Value[0] + '/'
            }

            # -- combine into complete action statement
            $action = "?tx=$($sig_request[0])&parent=$parent&v=2.6"
            $site = "https://$($e.'data-host')/frame/web/v1/auth"
            $uri = $site + $action

            $R = WebGet -uri $uri -maxRedirect 0 -basic $true -headers $headers

            # -- plugin form --
            Write-Verbose "plugin_form"
            $Parsed = $Parser.ParseDocument($R.Content)
            $form = $Parsed.forms | Where-Object ID -EQ 'plugin_form'
            $fields = @{}
            $form.elements | Where-Object type -NE 'fieldset' | ForEach-Object { $fields.add( $_.name, $_.value ) }
            $fields["java_version"] = ""
            $fields["flash_version"] = ""
            $fields["screen_resolution_width"] = "150"
            $fields["screen_resolution_height"] = "100"
            $fields["color_depth"] = "24"
            $fields["is_cef_browser"] = "false"
            $fields["is_ipad_os"] = "false"
            $fields["react_support"] = "true"

            $headers = @{}
            If (($R.BaseResponse).GetType().Name -eq 'HttpWebResponse') {
                $uri = $R.BaseResponse.ResponseUri.AbsoluteUri
            }
            else {
                # HttpsReponseMessage - powershell 6.2+
                $t = $R.BaseResponse.RequestMessage.RequestUri
                $uri = $t.OriginalString
                $headers["Origin"] = $t.Scheme + "://" + $t.DnsSafeHost
                $headers['Referer'] = $t.OriginalString
            }

            $R = WebPost -uri $uri -body $fields -MaxRedirect 5 -headers $headers

            # -- endpoint-health-form --
            Write-Verbose "endpoint-health-form"
            $Parsed = $Parser.ParseDocument($R.Content)
            $form = $Parsed.forms | Where-Object ID -EQ 'endpoint-health-form'
            $fields = @{}
            $form.elements | Where-Object type -NE 'fieldset' | ForEach-Object { $fields.add( $_.name, $_.value ) }

            $headers = @{}
            $headers["Cache-Control"] = "max-age=0"
            If (($R.BaseResponse).GetType().Name -eq 'HttpWebResponse') {
                $uri = $R.BaseResponse.ResponseUri.AbsoluteUri
            }
            else {
                # HttpsReponseMessage - powershell 6.2+
                $t = $R.BaseResponse.RequestMessage.RequestUri
                $uri = $t.OriginalString
                $headers["Origin"] = $t.Scheme + "://" + $t.DnsSafeHost
                $headers['Referer'] = $t.OriginalString
            }

            $R = WebPost -uri $uri -body $fields -MaxRedirect 5 -headers $headers

            # -- login-form --
            # xhr #1

            Write-Verbose "login-form xhr#1"
            $Parsed = $Parser.ParseDocument($R.Content)
            $form = $Parsed.forms | Where-Object ID -EQ 'login-form'
            $fields = @{}
            $form.elements | Where-Object { $_.type -NE 'fieldset' -and $_.parent.nodename -eq 'FORM' } | ForEach-Object { $fields.add( $_.name, $_.value ) }
            $fields["device"] = "phone1"
            $fields["factor"] = "Duo Push"
            $fields["out_of_date"] = "False"
            $fields["days_out_of_date"] = "0"
            $fields["days_to_block"] = "None"
            $null = $fields.Remove("url")
            $null = $fields.Remove("enrollment_message")
            $null = $fields.Remove("itype")
            $null = $fields.Remove("preferred_factor")
            $null = $fields.Remove("preferred_device")
            $null = $fields.Remove("passcode")
            $null = $fields.Remove("phone-smsable")
            $null = $fields.Remove("mobile-otpable")
            $null = $fields.Remove("next-passcode")
            $null = $fields.Remove("has-token")
            $null = $fields.Remove("dampen_choice")
            $null = $fields.Remove("should_update_dm")
            $null = $fields.Remove("should_retry_u2f_timeouts")
            $null = $fields.Remove("has_phone_that_requires_compliance_text")
            $null = $fields.Remove("ukey")

            $sid = urldecode $fields["sid"]

            $headers = @{}
            $headers["Accept"] = "text/plain, */*; q=0.01"
            $headers["X-Requested-With"] = "XMLHttpRequest"

            If (($R.BaseResponse).GetType().Name -eq 'HttpWebResponse') {
                $uri = [System.Uri]$R.BaseResponse.ResponseUri.AbsoluteUri
            }
            else {
                # HttpsReponseMessage - powershell 6.2+
                # $uri = [System.Uri]$R.BaseResponse.RequestMessage.RequestUri.AbsoluteUri

                $t = $R.BaseResponse.RequestMessage.RequestUri
                $uri = [System.Uri]$t.AbsoluteUri
                $headers["Origin"] = $t.Scheme + "://" + $t.DnsSafeHost
                $headers['Referer'] = $t.OriginalString
            }
            $uri = $uri.Scheme + "://" + $uri.Host + $form.Action

            $R2 = WebPost -uri $uri -body $fields -headers $headers

            $content = $R2.content | ConvertFrom-Json
            if ($content.stat -eq 'FAIL') {
                Write-Output $R2.content
                Write-Output "2-Factor NOT successful"
                return
            }

            # xhr #2

            # xhr #3

            # xhr #4


            # ------------------------------------------------------------
            # -- Poll for two-factor response
            # ------------------------------------------------------------
            Write-Verbose "Poll"
            $txid = ($R2.Content | ConvertFrom-Json).response.txid

            $headers = @{}
            $headers["Accept"] = "text/plain, */*; q=0.01"
            $headers["X-Requested-With"] = "XMLHttpRequest"

            If (($R.BaseResponse).GetType().Name -eq 'HttpWebResponse') {
                $uri = [System.Uri]$R.BaseResponse.ResponseUri.AbsoluteUri
            }
            else {
                # HttpsReponseMessage - powershell 6.2+
                $t = $R.BaseResponse.RequestMessage.RequestUri
                $uri = [System.Uri]$t.AbsoluteUri
                $headers["Origin"] = $t.Scheme + "://" + $t.DnsSafeHost
                $headers['Referer'] = $t.OriginalString
            }
            $uri = $uri.Scheme + "://" + $uri.Host + "/frame/status"
            $action = @{sid = $sid; txid = $txid }

            Write-Output "`nWaiting for 2-Factor response (30 seconds) ..."
            for ($i = 0; $i -lt 30; $i++) {
                Start-Sleep -Seconds 1

                $R2 = WebPost -uri $uri -body $action -headers $headers

                $content = $R2.content | ConvertFrom-Json
                $response = $content.response

                if ($response.result -eq "SUCCESS") {
                    Write-Output $response.status
                    break
                }
                if ($response.result -eq 'FAILURE') {
                    Write-Output $response.status
                    Write-Output "2-Factor NOT successful"
                    return
                }
                if ($content.stat -eq 'FAIL') {
                    Write-Output $response.status
                    Write-Output "2-Factor NOT successful"
                    return
                }
            }
            if ($i -gt 30) {
                Write-Output "2-Factor NOT received"
                return
            }
            if ($response.result -ne "SUCCESS") {
                Write-Output ($response | ConvertTo-Json)
                Write-Output "2-Factor NOT successful"
                return
            }

            #-- additional page
            $headers = @{}
            $headers["Accept"] = "text/plain, */*; q=0.01"
            $headers["X-Requested-With"] = "XMLHttpRequest"
            If (($R.BaseResponse).GetType().Name -eq 'HttpWebResponse') {
                $uri = [System.Uri]$R.BaseResponse.ResponseUri.AbsoluteUri
            }
            else {
                # HttpsReponseMessage - powershell 6.2+
                $t = $R.BaseResponse.RequestMessage.RequestUri
                $uri = [System.Uri]$t.AbsoluteUri
                $headers["Origin"] = $t.Scheme + "://" + $t.DnsSafeHost
                $headers['Referer'] = $t.OriginalString
            }
            $result_url = ($R2.content | ConvertFrom-Json).response.result_url
            $uri = $uri.Scheme + "://" + $uri.Host + $result_url
            $action = @{sid = $sid }

            $R = WebPost -uri $uri -body $action -headers $headers


            # ----------------------------------------------------


            $body = ($R.Content | ConvertFrom-Json).Response
            $uri = $body.Parent

            $Parsed = $Parser.ParseDocument($preDuoCasResponse.Content)
            $form = $Parsed.forms[0] # | Where-Object ID -EQ 'login-form'
            $fields = @{}
            $form.elements | Where-Object { $_.type -NE 'fieldset' -and $_.parent.nodename -eq 'FORM' } | ForEach-Object { $fields.add( $_.name, $_.value ) }

            # $form = $preDuoCasResponse.Forms[0]
            $fields.Add("signedDuoResponse", $body.cookie + ":" + $sig_request[1])

            $R = WebPost -uri $uri -body $fields -basic $true
        }
        Write-Verbose "post saml assertion to aws"

        $assertion = ($R.InputFields | Where-Object { $_.name -eq 'samlresponse' }).Value

        #-- auto post (passes assertion to amazonaws.com)
        $uri = [XML]$R.Content
        $uri = $uri.html.body.form.action
        
        $saml = WebPost -uri $uri -body @{SAMLResponse = $assertion }

        #-- select a role
        $account = Get-AWSAccount $saml

        Write-Verbose "[Use-STSRoleWithSAML]"
        try {
            $STSRole = Use-STSRoleWithSAML -RoleArn $account.RoleArn -PrincipalArn $account.PrincipalArn -SAMLAssertion $assertion -Region us-west-2 -DurationInSeconds 32400
        }
        catch {
            $STSRole = Use-STSRoleWithSAML -RoleArn $account.RoleArn -PrincipalArn $account.PrincipalArn -SAMLAssertion $assertion -Region us-west-2
        }

        $cred = $STSRole.Credentials
        Write-Output "`nCredential Expiration: $(Get-Date $STSRole.Credentials.Expiration -Format 'MM/dd/yyyy h:mm:ss tt' )" # -ForegroundColor Green

        Write-Verbose "[Set-AWSCredential]"
        $p = @{}
        $p.AccessKey = $cred.AccessKeyId
        $p.SecretKey = $cred.SecretAccessKey
        $p.SessionToken = $cred.SessionToken
        $p.ProfileLocation = "$env:userprofile\.aws\credentials"

        if (-not $noDefault.IsPresent) {
            $p.StoreAs = 'default'
            Set-AWSCredential @p
        }

        $p.StoreAS = $account.prettyname
        Set-AWSCredential @p

        If (-not (Get-DefaultAWSRegion)) {
            Write-Output "`n[Set-DefaultAWSRegion -region us-west-2]"
            Set-DefaultAWSRegion "us-west-2" -Scope Global
            Write-Output "  - setting region to us-west-2"
            Write-Output "  - enter Set-DefaultAWSRegion -us-west-2 in other powershell sessions"
            Write-Output '  or set the $StoredAWSRegion variable in your profile.'
        }
 
        Write-Verbose "[Get-IamAccountAlias]"
        $R = Get-IAMAccountAlias
        Write-Output "`nDefault AWS Account: $($R)" # -ForegroundColor Green

        Write-Verbose "[Get-STSCallerIdentity]"
        $R = Get-STSCallerIdentity | Select-Object Account, Arn, UserId
        Write-Output "`nUser Account : $($R.Account)"
        Write-Output "User Arn     : $($R.Arn)"
        Write-Output "UserId       : $($R.UserId)"
        Write-Output "`n"
    }

    End {
    }
}

Function Get-AWSAccount {
    param($saml_rsp)

    $Parsed = $Parser.ParseDocument($saml_rsp.Content)
    $form = $parsed.forms[0]
    $t = $form.outerHTML.Split("`n").Trim() | Select-String "Account:"

    # parse list of accounts
    $a = [ordered]@{}
    foreach ($l in $t) {
        $l = ([string]$l).replace('<div ', '').replace('</div>', '')
        $l = $l.Split(" ")
        $acctnbr = $l[2].Substring(1, $l[2].Length - 2)
        $a.$acctnbr = $l[1]
    }
    $accounts = [PSCustomObject]$a

    # parse saml assertion for account information
    $assertion = ($Parsed.Forms[0].Elements | Where-Object Name -EQ 'SAMLResponse').Value

    # $assertion = ($saml_rsp.InputFields | Where-Object { $_.name -eq "SAMLResponse" }).value
    $assertion_decode = [xml][text.encoding]::utf8.getstring([convert]::FromBase64String($assertion))
    $roles = $assertion_decode.Response.Assertion.AttributeStatement
    $roles = $roles.SelectNodes("*")
    $roles = $roles | Where-Object { $_.FriendlyName -eq "Role" }
    $roles = $roles.AttributeValue."#text"

    $list = foreach ($role in $roles) {
        $arn = $role.Split(",")[1]
        [PSCustomObject] @{
            rolearn      = $arn
            role         = $arn.Split(":")[5]
            acctnbr      = $arn.Split(":")[4]
            PrincipalArn = $role.Split(",")[0]
            prettyname   = $accounts.($arn.Split(":")[4])
        }
    }

    # create choice list for user
    $cnt = 1
    $width = [string] ([math]::floor([math]::log10($list.count - 1) + 1))
    $list = $list | Sort-Object prettyname, role

    $select = ""
    While (-not $select) {
        Write-Host ""
        $list | ForEach-Object {
            $a = $_.acctnbr
            $b = $_.prettyname
            $c = ($_.role)
            $c = $c.SubString(5, $c.Length - 5)
            Write-Host ("[{3,$width}] {0,-12} {1,-30} {2,-40}" -f $a, $b, $c, $cnt++)
            if (($cnt - 1) % 5 -eq 0) { Write-Host "" }
        }

        Write-Host ""
        $alias = Read-Host -Prompt "Select the role you would like to assume"
        $select = $list | Where-Object { $_.prettyname -eq $alias } | Select-Object -First 1
        $select = $list[$alias - 1]
    }
    Return $select
}

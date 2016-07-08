Set-StrictMode -Version Latest
function Terminate-User{
<# 
.Synopsis 
   Terminate-User executes a generalized sequence of tasks in Active Directory and Exchange when a user is terminated. 
.DESCRIPTION 
   Terminate-User does the following:
   -Disables ActiveSync
   -Disables ActiveDirectory Account
   -Removes from all groups besides Domain Users. Logs groups in case of later reversal.
   -Scrambles Password
   -Sets ActiveDirectory account's description to include SR#
   -Optionally sets an Automatic Reply
   -Optionally sets a forwarding address
   -Optionally grants Full Access permissions to a specified account
   -Removes user from GAL
   -Moves user into specified Inactive OU
   -Logs actions taken, and any errors encountered to the specified log
.NOTES 
   Author(s): Sean Slattery
   
   Version: 0.8
   Modified: 05/11/2016  
 
   To Implement:
    * Configuration file outside of module
    * Remote Exchange and Office 365 capabilities
    * User folder deletion and archival
.PARAMETER SR 
   SR should be the Service Request number from Connect Wise. Mandatory. Position 1
.PARAMETER UserEmail 
   The email address of the user to be terminated. Mandatory. Position 2  
.PARAMETER MailForwardingAddress 
   Optional. The email address to forward the terminated user's emails to. 
.PARAMETER MailAccessUser 
   Optional. The email address of the account to grant Full Access permissions to from the Terminated User's mailbox. 
.PARAMETER MailAutomaticReply
   Optional. Message that should be set for the Out of Office Message, both the internal and external will be the same.
.PARAMETER MailAutomaticReplyInternal
   Optional. Message that should be set for the internal Out of Office Message.
.PARAMETER MailAutomaticReplyExternal
   Optional. Message that should be set for the external Out of Office Message.
.EXAMPLE 
   Terminate-User 414415 jsmith@contoso.com
   The minimum required for this script to execute, using positional parameters for SR and UserEmail 
.EXAMPLE 
   Terminate-User -SR 414415 -UserEmail jsmith@contoso.com -MailAutomaticReply "Hello, jsmith no longer works here."
   Terminates the user and sets an Out of Office Message for everyone.
.EXAMPLE 
   Terminate-User -SR 999999 -UserEmail jsmith@contoso.com -MailAutomaticReplyInternal "Jack was bad. So we fired him"
   Terminates the user and sets an Out of Office Message only for Internal members of the organization 
.EXAMPLE 
   Terminate-User -SR 999999 -UserEmail jsmith@contoso.com -MailForwardingAddress bob.smith@contoso.com -MailAccessUser bob.smith@contso.com -MailAutomaticReplyInternal "Jack was quack"
   Terminates the user. Sets a forwarding address and grants full access permissions to Bob Smith. Also sets an Out of Office Message only for Internal members of the organization 
#>
[CmdletBinding(SupportsShouldProcess=$true,DefaultParameterSetName = 'Auto')]
Param(
    
    [Parameter(Mandatory=$True,Position=1,ParameterSetName='Auto')]
    [Parameter(Mandatory=$True,Position=1,ParameterSetName='IntExt')]
    [ValidatePattern("^[0-9]{6}$")][String]$SR,
   
    [Parameter(Mandatory=$True,Position=2,ParameterSetName='Auto')]
    [Parameter(Mandatory=$True,Position=2,ParameterSetName='IntExt')]
    [ValidateNotNullOrEmpty()][String]$UserEmail,
      
    [Parameter(Mandatory=$False,ParameterSetName='Auto')]
    [Parameter(Mandatory=$False,ParameterSetName='IntExt')]
    [String]$MailForwardingAddress,
    
    [Parameter(Mandatory=$False,ParameterSetName='Auto')]
    [Parameter(Mandatory=$False,ParameterSetName='IntExt')]
    [String]$MailAccessUser,
    
    [Parameter(Mandatory=$False,ParameterSetName='Auto')]
    [String]$MailAutomaticReply,
    
    [Parameter(Mandatory=$False,ParameterSetName='IntExt')]
    [String]$MailAutomaticReplyInternal,
    
    [Parameter(Mandatory=$False,ParameterSetName='IntExt')]
    [String]$MailAutomaticReplyExternal
)
Try{
    #CONFIGURATION VARIABLES
    ########################
    $INACTIVE_OU_NAME = 'Terminated_Users'
    $global:PATH_TO_LOG = 'C:\Logs\Terminate-Users.log'
    ########################
    Import-Module Write-Log -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction Stop
    
    $Domain = Get-ADDomain
    $DomainDN = $Domain.DistinguishedName
    $INACTIVE_OU = "OU=$INACTIVE_OU_NAME,$DomainDN"
    Try{
       New-ADorganizationalUnit -Name $INACTIVE_OU_NAME -Path $DomainDN -ProtectedFromAccidentalDeletion:$false 
    }catch{
    }
    $StartTime = Get-Date
}
catch{
    $ErrorMessage = ($_ | Out-String)
    Write-Log -Message $ErrorMessage -Level Error -Path $PATH_TO_LOG
    Exit
}

#MAIN FUNCTION    
Try{
    Write-Log -Message "Terminate-User -SR $SR -UserEmail $UserEmail" -Path $PATH_TO_LOG
    $ValidatedUser = Validate-User -UserToBeValidated $UserEmail
    $confirmation = 'y'
    #$confirmation = Read-Host "$ValidatedUser will be terminated. Are you Sure You Want To Proceed? [y/N]"
    if ($confirmation -eq 'y') {
        Set-CASMailbox -Identity $ValidatedUser -OWAEnabled $false -PopEnabled $false -ActiveSyncEnabled $false -ECPEnabled $false -EwsEnabled $false -ImapEnabled $false -MAPIEnabled $false
        Write-Log -Message "Disabled ActiveSync, POP, ECP, EWS, IMAP, MAPI, OWA" -Path $PATH_TO_LOG
        Disable-CustomRules -ADAccount $ValidatedUser
        Disable-ADAccount -Identity $ValidatedUser
        Write-Log "Disabled ActiveDirectory Account" -Path $PATH_TO_LOG
        Remove-Groups -UserToRemoveGroups $ValidatedUser 
        Set-ScrambledPassword -SamAccountName $ValidatedUser
        Set-ADUser -Identity $ValidatedUser -description "Terminated by Terminate-User on $StartTime. SR# $SR"
        Write-Log "Set AD Description: Terminated by Script on $StartTime. SR# $SR"
        Set-AutomaticReply -UserToSetAutoReply $ValidatedUser -MailAutomaticReply $MailAutomaticReply -MailAutomaticReplyInternal $MailAutomaticReplyInternal -MailAutomaticReplyExternal $MailAutomaticReplyExternal
        Try{
            if($MailForwardingAddress){
                Set-Mailbox -Identity $ValidatedUser -ForwardingAddress $MailForwardingAddress -DeliverToMailboxAndForward $True
                Write-Log "Setup mail forwarding to: $MailForwardingAddress" -Path $PATH_TO_LOG
            }
            else{
                Set-Mailbox -Identity $ValidatedUser -DeliverToMailBoxAndForward $false -ForwardingSmtpAddress $null
                Write-Log "Disabled mail forwarding" -Path $PATH_TO_LOG
            }
        }
        catch{
            $ErrorMessage = ($_ | Out-String)
            Write-Log -Message $ErrorMessage -Level Error -Path $PATH_TO_LOG
        }    
        Try{
            if($MailAccessUser){
                Add-MailboxPermission -Identity $ValidatedUser -User $MailAccessUser -AccessRights FullAccess -AutoMapping $True
                Write-log "Granted Full Access Permission to: $MailAccessUser" -Path $PATH_TO_LOG
            }
        }catch{
            $ErrorMessage = ($_ | Out-String)
            Write-Log -Message $ErrorMessage -Level Error
        }
        Set-Mailbox -Identity $ValidatedUser -HiddenFromAddressListsEnabled $True
        Write-Log "Hidden from GAL" -Path $PATH_TO_LOG
        #Move-ADObject only works with Distinguished Names
        $TempUser = Get-ADUser -Identity $ValidatedUser 
        Move-ADObject -Identity $TempUser.DistinguishedName -TargetPath $INACTIVE_OU
        Write-Log "Moved account to: $INACTIVE_OU" -Path $PATH_TO_LOG
        $EndTime = Get-Date
        $TotalRuntime = ($EndTime - $StartTime).TotalSeconds
        Write-Log -Message "Terminate-User finished executing in $TotalRuntime seconds." -Path $PATH_TO_LOG
        Return 1
    }
    else{
        Exit
    }
    }
catch{
    $Error1 = $_
    Write-Host $error1.categoryinfo
    $ErrorMessage = ($Error1 | Out-String)
    Write-Log -Message $ErrorMessage -Level Error -Path $PATH_TO_LOG
}
}


function Validate-User{
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()]$UserToBeValidated
)
    Try{
        $ValidatedUser = (Get-MailBox -Identity $UserToBeValidated).samaccountname
        #Trying to prohibit Wildcard characters or multiple users
        $Test = Get-ADUser -Identity $ValidatedUser
        Write-Log -Message "Validated User: $ValidatedUser" -Path $PATH_TO_LOG
        Return $ValidatedUser
    }
    catch{
        $ErrorMessage = ($_ | Out-String)
        Throw "Fatal Error. Invalid Input or Exchange Environment Not Present. Error: $ErrorMessage" 
}
}


function Remove-Groups{
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()]$UserToRemoveGroups
)
   Try{
        $ADgroups = Get-ADPrincipalGroupMembership -Identity $UserToRemoveGroups | where {$_.Name -ne "Domain Users"}
        if($ADgroups){
            Remove-ADPrincipalGroupMembership -Identity $UserToRemoveGroups -MemberOf $ADgroups -Confirm:$false
            Write-Log "Removed $UserToRemoveGroups from: $ADgroups" -Path $PATH_TO_LOG
            return $ADgroups  
        }
        else{
            Write-Log "Removed $UserToRemoveGroups from: 0 Groups" -Path $PATH_TO_LOG
        }    
    }
    catch{
        $ErrorMessage = ($_ | Out-String)
        Write-Log -Message $ErrorMessage -Level Error -Path $PATH_TO_LOG
    }
}


function Set-AutomaticReply{
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()]$UserToSetAutoReply,
    [Parameter(Mandatory=$False)][String]$MailAutomaticReply,
    [Parameter(Mandatory=$False)][String]$MailAutomaticReplyInternal,
    [Parameter(Mandatory=$False)][String]$MailAutomaticReplyExternal

)
   Try{
        if($MailAutomaticReply){
            Set-MailboxAutoReplyConfiguration -Identity $ValidatedUser -AutoReplyState enabled -ExternalAudience all -InternalMessage $MailAutomaticReply -ExternalMessage $MailAutomaticReply 
            Write-Log "AutomaticReply Set" -Path $PATH_TO_LOG
        }
        elseif($MailAutomaticReplyInternal){
            #Should ExternalAudience Be set to None?
            Set-MailboxAutoReplyConfiguration -Identity $ValidatedUser -AutoReplyState enabled -ExternalAudience all -InternalMessage $MailAutomaticReplyInternal -ExternalMessage $MailAutomaticReplyExternal
            Write-Log "AutomaticReplyInternal Set" -Path $PATH_TO_LOG
        }
        elseif($MailAutomaticReplyExternal){
            Set-MailboxAutoReplyConfiguration -Identity $ValidatedUser -AutoReplyState enabled -ExternalAudience all -InternalMessage $MailAutomaticReplyInternal -ExternalMessage $MailAutomaticReplyExternal
            Write-Log "AutomaticReplyExternal Set" -Path $PATH_TO_LOG
        }
      
    }
    catch{
        $ErrorMessage = ($_ | Out-String)
        Write-Log -Message $ErrorMessage -Level Error -Path $PATH_TO_LOG
    }
}


Function New-Password() {
[CmdletBinding()]
Param(
[int]$length=14,
[string[]]$alphabet
)
For ($a=33;$a –le 126;$a++) {$alphabet+=,[char][byte]$a }
For ($loop=1; $loop –le $length; $loop++) {
    $NewPassword+=($alphabet | GET-RANDOM)
}
return $NewPassword
}


function Set-ScrambledPassword{
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][String]$SamAccountName
)
Try{
    Import-Module Write-Log -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction Stop

    $Password = New-Password | ConvertTo-SecureString -AsPlainText -Force
    Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword $Password
    Write-Log -Message "Scrambled Password" -Path $PATH_TO_LOG
}
catch{
    $ErrorMessage = ($_ | Out-String)
    Write-Log -Message $ErrorMessage -Level Error -Path $PATH_TO_LOG
}
}


function Disable-CustomRules {
[cmdletbinding()]
Param(
    [string]$ADAccount
)
Try{
    $Rules = Get-InboxRule -Mailbox $ADAccount
    if(!$Rules){
        Write-Log "Disabled custom inbox rules: None" -Path $PATH_TO_LOG
        return 
    }
    foreach ($Rule in $Rules) {
    $RuleID = $Rule.Name
    Disable-InboxRule -Mailbox $ADAccount -Identity $RuleID -Force 
    Write-Log "Disabled custom inbox rules: $Rules" -Path $PATH_TO_LOG   
}
}catch{
    $ErrorMessage = ($_ | Out-String)
    Write-Log -Message $ErrorMessage -Level Error -Path $PATH_TO_LOG
}

}




Export-ModuleMember Terminate-User,Set-ScrambledPassword,Remove-Groups
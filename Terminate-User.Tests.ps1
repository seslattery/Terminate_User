Try{
    Remove-Module Terminate-User
    Remove-Module ActiveDirectory
}catch{}
Import-Module Terminate-User
Import-Module ActiveDirectory
Import-Module Write-Log




InModuleScope Terminate-User {
    Describe "Terminate-User" {
        BeforeEach{
            ################################
            #OPTIONAL CONFIGURATION VARIABLES
            $OU_NAME = "PesterTests"
            $DL_NAME = "PesterTestsDL"
            ################################
            $Domain = Get-ADDomain
            $DomainDN = $Domain.DistinguishedName
            $1st = $DomainDN.split(',').substring(3)[0]
            $2nd = $DomainDN.split(',').substring(3)[1]
            $UPNSuffix = "$1st.$2nd"
            $OU_FullPath = "OU=$OU_NAME,$DomainDN"
            $DL_FullPath = "CN=$DL_NAME,CN=Users,$DomainDN"
            $OU = $OU_FullPath.split(',').substring(3)[0]
            $DL = $DL_FullPath.split(',').substring(3)[0]
            $Password = ConvertTo-SecureString "P@ssW0rd123" -AsPlainText -Force

            # Create the new OU for our Test Users
            Try{
                 New-ADorganizationalUnit -Name $OU -Path $DomainDN -ProtectedFromAccidentalDeletion:$false 
            }catch{Write-Host ($_ | Out-String)}
            Try{
                 New-DistributionGroup -Name $DL
            }catch{Write-Host ($_ | Out-String)}
            $Username ="Bob.Smith"
            $Firstname = "Bob"
            $LastName = "Smith"
            $DisplayName = "Bob Smith"
            $UPN = "$($Username)@$($UPNSuffix)"
            Try{
                New-Mailbox -Name $DisplayName -SamAccountName $Username -UserPrincipalName $UPN -Alias $Username  -OrganizationalUnit $OU -Password $Password -FirstName $FirstName -LastName $LastName 
            }catch{Write-Host ($_ | Out-String)}
            Try{
                 Add-DistributionGroupMember -Identity $DL -Member $Username
            }catch{Write-Host ($_ | Out-String)}
         
        }
        
        Context "Parameters and Help"{
        
            Set-StrictMode -Version latest

            It "SR should be mandatory, and only accept 6 digits"{
                {Terminate-User -SR 12345 -UserEmail $UPN} | Should Throw
                {Terminate-User -SR AAAAAA -UserEmail $UPN} | Should Throw
                {Terminate-User -SR 1234567 -UserEmail $UPN} | Should Throw
                {Terminate-User -SR 12345A -UserEmail $UPN} | Should Throw
                {Terminate-User -SR $NULL -UserEmail $UPN} | Should Throw
                {Terminate-User -SR "" -UserEmail $UPN} | Should Throw
                {Terminate-User -SR ****** -UserEmail $UPN} | Should Throw
            }

            It "UserEmail should be mandatory"{
                {Terminate-User -SR 123456 -UserEmail $NULL} | Should Throw
                {Terminate-User -SR 123456 -UserEmail ""} | Should Throw
            }

            It "Should not allow AutomaticReply to be set when either ARInteral or ARExternal are set"{
                {Terminate-User -SR 123456 -UserEmail $UPN -MailAutomaticReply "1" -MailAutomaticReplyInternal "2"} | Should Throw
            }

            It "Should have built in help along with Description and Examples" {
                $helpinfo = Get-Help Terminate-User
                $helpinfo.examples | Should not BeNullOrEmpty  # should have examples
                $helpinfo.Details | Should not BeNullOrEmpty   # Should have Details in the Help
                $helpinfo.Description | Should not BeNullOrEmpty # Should have a Description for the Function
            }
        }

        Context "Functions" {
            
            It "Validate-User should return a valid user from AD"{
                $ValidatedUser = Validate-User -UserToBeValidated Bob.Smith
                $ValidatedUser | Should Not BeNullOrEmpty
                $ValidatedUser | Should Be $Username
            }
            It "Validate-User should prevent wildcards"{
                {Validate-User -UserToBeValidated *} | Should Throw
            }
                
            It "Remove-Groups should return groups"{
                $Groups = Remove-Groups -UserToRemoveGroups $Username
                $Groups | Should Not BeNullOrEmpty #Double Check AD User is a member of groups or this test will fail
                $Groups | Should Be $DL_FullPath
            }

            It "Remove-Groups should not throw an error for null groups"{
                Try{
                    $ADgroups = Get-ADPrincipalGroupMembership -Identity $Username | where {$_.Name -ne "Domain Users"}
                    Remove-ADPrincipalGroupMembership -Identity $Username -MemberOf $ADgroups -confirm:$false
                    {Remove-Groups -UserToRemoveGroups $Username} | Should Not Throw
                
                }
                catch{
                    Write-Host ($_ | Out-String)
                }
            }
       
            It "New-Password creates a new password that is not null and of a specified length"{
                $Password = New-Password -length 10
                $Password | Should Be $true
                ($Password).length |Should Be 10
            }
        
        
            It "Set-ScrambledPassword should throw an exception if SamAccountName is null or empty"{
                {Set-ScrambledPassword -sAMAccountName ""} |Should Throw
                {Set-ScrambledPassword -sAMAccountName $NULL} |Should Throw 
            }
            
            It "Basic Integration Test" {
                $A = Terminate-User -SR 123456 -UserEmail $UPN
                #Using Implicit Array and negative indexing to access the last return value from Terminate-User
                $A[-1] | Should Be 1
            } 
            It "Full Integration Test. Terminate-User should return 1 on succesful completion"{
                $Username2 ="James.Jones"
                $Firstname2 = "James"
                $LastName2 = "Jones"
                $DisplayName2 = "James Jones"
                New-Mailbox -Name $DisplayName2 -SamAccountName $Username2 -UserPrincipalName "$($Username2)@$($UPNSuffix)" -Alias $Username2  -OrganizationalUnit $OU -Password $Password -FirstName $FirstName2 -LastName $LastName2
                Try{
                    Add-DistributionGroupMember -Identity $DL -Member $Username2
                }catch{Write-Host ($_ | Out-String)}
                $A = Terminate-User -SR 123456 -UserEmail $UPN -MailForwardingAddress James.Jones@test.local -MailAccessUser James.Jones@test.local -MailAutomaticReply "A" 
                #Using Implicit Array and negative indexing to access the last return value from Terminate-User
                $A[-1] | Should Be 1
                Remove-Mailbox "James.Jones" -confirm:$false
            }

            
        }

        AfterEach{
            
           Try{
               $ADgroups = Get-ADPrincipalGroupMembership -Identity $Username | where {$_.Name -ne "Domain Users"}
               Remove-ADPrincipalGroupMembership -Identity $Username -MemberOf $ADgroups -confirm:$false
           }catch{}
           Try{   
               Remove-DistributionGroup $DL -confirm:$false
           }catch{Write-Host ($_ | Out-String)}
           Try{
               Remove-Mailbox "Bob.Smith" -confirm:$false
           }catch{Write-Host ($_ | Out-String)}
           Try{
               Remove-ADorganizationalUnit $OU_FullPath -confirm:$false
           }catch{Write-Host ($_ | Out-String)}  
       }
    }
}
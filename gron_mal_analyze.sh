#!/bin/bash

# Add modular execution

RED='\033[1;31m'
BLUE='\033[1;34m'
GREEN='\033[1;32m'
YELLOW='\033[49;93m'
NC='\033[0m' # No Color

echo -e "${YELLOW}"
echo -e "+---_-------------------------------------------------+"
echo -e "|  Adversarial Informatics Malware Behavior Analysis  |"
echo -e "|               cygienesolutions.com                  |"
echo -e "|      [Usage]: ./gt_mal_analyze.sh <FILE>            |"
echo -e "+-----------------------------------------------------+"
echo -e "${NC}"
if [ $# == 0 ] ; then
    echo -e "${GREEN}"
    echo -e "Description:"
    echo -e "Evaluates Malware Behavior Logs for Bad Signatures"
    echo -e ""
    echo -e "[Usage]: ./gt_mal_analyze.sh filename.json"
    echo -e "${NC}"
    exit 1; fi

FILENAME="$1"
scanReport=()

#	A. Registry Keys Written
echo -e "${GREEN}"
echo -e "[!] Checking for newly created registry keys"
echo -e "${NC}"
declare -a arr=("regkey_written")
# "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			#scanReport+=("[-] Registry key creation detected")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			scanReport+=("")
			unbuffer unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done


#	A. Malware sets itself to run whenever Windows starts up
echo -e "${GREEN}"
echo -e "[!] Checking for startup persistence modification"
echo -e "${NC}"
declare -a arr=("Run" "RunOnce")
# "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce" "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep "regkey_written" | fgrep --line-number $i; then
			scanReport+=("[+] Autostartup/Persistence activity detected")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			scanReport+=("")
			unbuffer unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done

#	Malware looks up the computer name (possibly doing some reconnaissance)
echo -e "${GREEN}"
echo -e "[!] Malware looks up the computer name"
echo -e "${NC}"
#"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName")
declare -a arr=("GetComputerName" "GetComputerNameW" "ActiveComputerName")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep -n -q $i; then
			scanReport+=("[+] Malware looks up the computer name")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done


#	Potentially looks through Microsoft Outlook address book contents
echo -e "${GREEN}"
echo -e "[!] Potentially looks through Microsoft Outlook address book contents"
echo -e "${NC}"
declare -a arr=("Outlook.Application")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] Outlook.Application reference activity detected.")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
#	Creates and executes a Visual Basic Script (VBS) called “WinVBS.vbs
echo -e "${GREEN}"
echo -e "[!] Creates and executes a Visual Basic Script (VBS) called “WinVBS.vbs"
echo -e "${NC}"
declare -a arr=("WinVBS.vbs")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] Creates and executes a Visual Basic Script (VBS) called “WinVBS.vbs")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done

#	Prevents users from accessing registry tools
echo -e "${GREEN}"
echo -e "[!] Prevents users from accessing registry tools"
echo -e "${NC}"
declare -a arr=("DisableRegistryTools")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] Prevents users from accessing registry tools")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
#	Hides all drives on computer
echo -e "${GREEN}"
echo -e "[!] Hides all drives on computer"
echo -e "${NC}"
declare -a arr=("0x03FFFFFF")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] Hides all drives on computer")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
#	Prevents users from changing (Remote Administrator) (Account Control Group Policy) or -registry-key-settings
echo -e "${GREEN}"
echo -e "[!] Prevents users from changing remote administrator settings account-control-group-policy-and-registry-key-settings"
echo -e "${NC}"
declare -a arr=("NoAdminPage" "FilterAdministratorToken" "EnableUIADesktopToggle" "ConsentPromptBehaviorAdmin" "ConsentPromptBehaviorUser" "EnableInstallerDetection" "ValidateAdminCodeSignatures" "EnableSecureUIAPaths" "EnableLUA" "PromptOnSecureDesktop" "EnableVirtualization")
# "FilterAdministratorToken" "EnableUIADesktopToggle" "ConsentPromptBehaviorAdmin" "ConsentPromptBehaviorUser" "EnableInstallerDetection" "ValidateAdminCodeSignatures" "EnableSecureUIAPaths" "EnableLUA" "PromptOnSecureDesktop" "EnableVirtualization" "FilterAdministratorToken" "EnableUIADesktopToggle" "ConsentPromptBehaviorAdmin" "ConsentPromptBehaviorUser" "EnableInstallerDetection" "ValidateAdminCodeSignatures" "EnableSecureUIAPaths" "EnableLUA" "PromptOnSecureDesktop" "EnableVirtualization")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] Remote admin settings change prevention evidence detected")
#                    echo -e "${NC}"
		    #echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
#	Prevents users from changing remote administrator settings account-control-group-policy-and-registry-key-settings
#echo -e "${GREEN}"
#echo -e "Prevents users from changing remote administrator settings account-control-group-policy-and-registry-key-settings"
#echo -e "${NC}"
#declare -a arr=("0x03FFFFFF" "FilterAdministratorToken" "EnableUIADesktopToggle" "ConsentPromptBehaviorAdmin" "ConsentPromptBehaviorUser" "EnableInstallerDetection" "ValidateAdminCodeSignatures" "EnableSecureUIAPaths" "EnableLUA" "PromptOnSecureDesktop" "EnableVirtualization" "FilterAdministratorToken" "EnableUIADesktopToggle" "ConsentPromptBehaviorAdmin" "ConsentPromptBehaviorUser" "EnableInstallerDetection" "ValidateAdminCodeSignatures" "EnableSecureUIAPaths" "EnableLUA" "PromptOnSecureDesktop" "EnableVirtualization" "NoCommonGroups" "NoDeletePrinter" "NoAddPrinter" "NoRun" "NoSetFolders" "NoSetTaskbar" "NoFind" "NoDrives" "NoNetHood" "NoDesktop" "NoClose" "NoSaveSettings" "DisableRegistryTools" "NoRecentDocsMenu" "NoRecentDocsHistory" "NoFileMenu" "NoActiveDesktop" "NoActiveDesktopChanges" "NoInternetIcon" "NoFavoritesMenu" "NoChangeStartMenu" "NoFolderOptions" "NoSetFolders" "ClearRecentDocsOnExit" "NoLogoff" "NoSetTaskbar" "NoTrayContextMenu" "NoStartMenuSubFolders" "NoWindowsUpdate" "NoViewContextMenu" "EnforceShellExtensionSecurity" "LinkResolveIgnoreLinkInfo" "NoDriveTypeAutoRun" "NoStartBanner" "NoEntireNetwork" "NoWorkgroupContents" "EditLevel" "NoNetConnectDisconnect" "RestrictRun" "NoDispCPL" "NoDispBackgroundPage" "NoDispScrSavPage" "NoDispAppearancePage" "NoDispSettingsPage" "NoSecCPL" "NoPwdPage" "NoAdminPage" "NoProfilePage" "NoDevMgrPage" "NoConfigPage" "NoFileSysPage" "NoVirtMemPage" "NoNetSetupSecurityPage" "NoNetSetup" "NoNetSetupIDPage" "NoNetSetupSecurityPage" "NoFileSharingControl" "NoPrintSharing" "WinOldAppkey" "NoRealMod")
##for i in "${arr[@]}"
#	do
#		if gron $1 | fgrep --line-number -q $i; then
#			scanReport+=("")
#                    echo -e "${NC}"
#		    #echo $1     [+] $i
#			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
#		fi
#	done
	
	
#	Checks for its privileges 
echo -e "${GREEN}"
echo -e "[!] Checks for its privileges "
echo -e "${NC}"
declare -a arr=("LookupPrivilegeValueA" "lpSystemName" "lpName" "lpSystemName" "lpLuid")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] Privilege checking detected.")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
#	Hooks the keyboard (potentially a keylogger)
echo -e "${GREEN}"
echo -e "[!] Hooks the keyboard (potentially a keylogger)"
echo -e "${NC}"
declare -a arr=("SetWindowsHookExA" "WH_KEYBOARD") 
# "WH_KEYBOARD" "WH_KEYBOARD_LL" "WH_CALLWNDPROC" "WH_CALLWNDPROC" "WH_CBT" "WH_DEBUG" "WH_FOREGROUNDIDLE" "WH_GETMESSAGE" "WH_JOURNALPLAYBACK" "WH_JOURNALRECORD" "WH_JOURNALRECORD" "WH_JOURNALRECORD" "WH_MSGFILTERWH_SHELL" "WH_SYSMSGFILTER" "SetWindowsHookEx" "lpfn" "hmod" "dwThreadId" "User32.dll" "winuser.h"
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] Keyboard hooking detected.")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
#	Hooks the mouse
echo -e "${GREEN}"
echo -e "[!] Hooks the mouse"
echo -e "${NC}"
declare -a arr=("WH_MOUSE" "WH_MOUSE_LL")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] Mouse hooking detected.")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	

#	Potentially monitors messages before they appear in a window to the user (possible reconnaissance)
echo -e "${GREEN}"
echo -e "[!] Potentially monitors messages before they appear in a window to the user (possible reconnaissance)"
echo -e "${NC}"
declare -a arr=("WH_CALLWNDPROC")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] Windows Process handler monitoring detected.")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	

#	Communicates with external hosts via IP addresses or domain names, possibly indicative of C2 activity.
# IP and HOstname regex up in this piece
echo -e "${GREEN}"
echo -e "[!] Communicates with external hosts via IP addresses or domain names, possibly indicative of C2 activity."
echo -e "${NC}"
declare -a arr=("ip_address")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] C2/External Host activity evidence found")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
#	Retrieves the current user’s username
echo -e "${GREEN}"
echo -e "[!] Retrieves the current user’s username"
echo -e "${NC}"
declare -a arr=("GetUserNameA")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] Current user's username retrieval")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
#	All encompassing Mutex search
echo -e "${GREEN}"
echo -e "[!] Searching for all evidence if mutex activity"
echo -e "${NC}"
declare -a arr=("mutex")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			#scanReport+=("[+] Mutex activity found:")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
	
#	Adds mutex for Eclipse DDoS malware
echo -e "${GREEN}"
echo -e "[!] Adds mutex for Eclipse DDoS malware"
echo -e "${NC}"
declare -a arr=("eclipseddos")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("               [+] Eclipse DDoS malware found")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
	
#	Adds mutex for IPKillerClient malware  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# NEEDED
echo -e "${GREEN}"
echo -e "[!] Adds mutex for IPKillerClient malware"
echo -e "${NC}"
declare -a arr=("ddos_ipkiller_mutexes")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("               [+] IPKillerClient mutex evidence found")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
	
#	Adds mutex for DarkDDoSer malware  !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# NEEDED
echo -e "${GREEN}"
echo -e "[!] Adds mutex for DarkDDoSer malware"
echo -e "${NC}"
declare -a arr=("darkddos" "Dark-DDos")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("               [+] DarkDDoSer mutex evidence found")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
	
#	Contacts various SMTP servers (possibly for spamming)
# NEEDED
echo -e "${GREEN}"
echo -e "[!] Contacts various SMTP servers (possibly for spamming)"
echo -e "${NC}"
declare -a arr=("smtp.")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] SMTP Servers contacted")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
#	Copies potentially malicious files to the device !!!!!!!!!!!!.
# NEEDED
echo -e "${GREEN}"
echo -e "[!] Copies potentially malicious files to the device. !!!!!!!!!!!!!!!!!"
echo -e "${NC}"
declare -a arr=("dropped")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep --line-number -q $i; then
			scanReport+=("[+] Dropped malicious files to the device")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done
	
#	Adds a malicious cryptographic certificate to the system
# NEEDED
echo -e "${GREEN}"
echo -e "[!] Adds a malicious cryptographic certificate to the system."
echo -e "${NC}"
declare -a arr=("SystemCertificates")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep "regkey_written" | fgrep --line-number $i; then
			scanReport+=("[+] Cryptographic certificate to the system evidence found.")
			scanReport+=("        $(unbuffer gron $1 | fgrep -n $i)")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done	

#	Buffer and communications evaluation
# NEEDED
echo -e "${GREEN}"
echo -e "[!] Buffer and communications evaluation"
echo -e "${NC}"
declare -a arr=("GET" "POST" "password" "Host:")
for i in "${arr[@]}"
	do
		if gron $1 | fgrep "buffer" | fgrep --line-number $i; then
			#scanReport+=("[+] Buffer and communications content found.")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			scanReport+=("")
			unbuffer gron $1 | fgrep -n $i
#		    echo -e "${NC}"
		fi
	done	


#	Scan file for IP address regex match.
# NEEDED
echo -e "${GREEN}"
echo -e "[!] Network IP Address Regex Search"
echo -e "${NC}"
declare -a arr=("([0-9]{1,3}[\.]){3}[0-9]{1,3}")
for i in "${arr[@]}"
	do
		if grep -B 1 -A 1 -n -q -E -o $i $1; then
			scanReport+=("[+] IP address regex match.")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			grep -E -o $i $1 | uniq
			#grep -C 2 \"$(grep -E -o $i $1)\" $1
#		    echo -e "${NC}"
		fi
	done
	
	

#	Scan file for IP address regex match.
# NEEDED
echo -e "${GREEN}"
echo -e "[!] Network Domain/Hostname Regex Search"
echo -e "${NC}"
declare -a arr=("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$")
for i in "${arr[@]}"
	do
		if grep -B 1 -A 1 -n -q -E -o $i $1; then
			scanReport+=("[+] Network Domain/Hostname regex match.")
#                    echo -e "${NC}"
		    echo $1     [+] $i
			grep -E -o $i $1 | uniq
			#grep -C 2 \"$(grep -E -o $i $1)\" $1
#		    echo -e "${NC}"
		fi
	done
	
	

echo -e "${YELLOW}"
echo -e "[!] Scan Report: $1"
echo -e "${NC}"
for value in "${scanReport[@]}"
do
	echo -e "     " $value
done
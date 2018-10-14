# HWFWBypass
==========
This program can be used to bypass/fool hardware firewalls.
The program has to be started with administrator level privileges on a server.
When a client connects from the TCP source port specified in the client_sourceport parameter,
to the TCP destination port original_dstport. the kernel driver will redirect the traffic to the
new_dstport on the server. 
This trick is useful when the restrictive firewall is blocking bind shells,
or thwarting log analysis, because all traffic will use legitimate service port.


## Usage 
hwfwbypass.exe client_sourceport original_dstport new_dstport [disablechecksum] [debug]

### Examples
hwfwbypass.exe 1337 3389 31337 
hwfwbypass.exe 1337 3389 31337 disablechecksum debug

disablechecksum: when this parameter is set, it will disable the calculation of the TCP or IP checksums. 
It is useful when the network adapter driver does the checksum calculations (offload).

debug: print debug info on the screen about the original and modified traffic.


## Compilation notes
Download http://reqrypt.org/download/WinDivert-1.1.4-MSVC.zip or later from http://reqrypt.org/windivert.html 
Update packages in windivert_32_lib or windivert_x64_lib
Copy the compiled windivert files (dll, sys) to the compiled hwfwbypass directory (32/64, debug/release)

## Known problems, errors

error: failed to open the WinDivert device (5)

solution: Start the executable with administrator level privileges. Check if the DLL and SYS file is in the same directory. 

-------------------

error: msvcrxxx.dll is missing:

solution:
Download the corresponding Microsoft Visual Studio redistributable files, and either install it, or put the DLL's in the 
same directory where the hwfwbypass binary is.
msvcr110.dll -> Visual studio 2012
msvcr120.dll -> Visual studio 2013
Always install the same architecture (32/64 bit) of the DLL as it is the binary.
Additional information: the windivert dll file has been compiled with VS2012, and hwfwbypass has been compiled with VS2013

## Limitations

1. The bind shell should listen on the same interface where the service with original_dstport listens. The driver can't forward the traffic to the "non-existent" loopback interface.

2. Only TCP traffic is supported at the moment.

![logo][logo]

[logo]: https://raw.githubusercontent.com/MRGEffitas/hwfwbypass/master/hwfwbypass_logo.jpg "HWFWBypass"

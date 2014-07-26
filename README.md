hwfwbypass
==========

Download http://reqrypt.org/download/WinDivert-1.1.4-MSVC.zip or later from http://reqrypt.org/windivert.html 
Update packages in windivert_32_lib or windivert_x64_lib
Copy the compiled windivert files (dll, sys) to the compiled hwfwbypass directory (32/64, debug/release)


usage: hwfwbypass.exe client_sourceport original_dstport new_dstport [disablechecksum] [debug]
examples:
hwfwbypass.exe 1337 3389 31337 
hwfwbypass.exe 1337 3389 31337 disablechecksum debug
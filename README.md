# COM-Code-Helper
Two IDAPython Scripts helping you to reconstruct Microsoft COM (Component Object Model) Code
Especially malware reversers will find this useful, as COM Code is still regularly found in malware.

# ClassAndInterfaceToNames.py
This IDAPython script scans an idb file for class and interfaces UUIDs and creates the matching structure and its name.
Make sure to copy interfaces.txt + classes.txt is in the same directory as ClassAndInterfaceToNames.py


# Microsoft-SDK-Vtable-Structs.py
This IDAPython script creates vtables derrived from Microsoft SDK.


To learn about COM check out the Microsoft website--> https://docs.microsoft.com/en-us/windows/win32/com/the-component-object-model

Code was tested on IDA 7.4 and Python versions 2+3

![Alt text](relative/code/COM-Code-Original1.PNGimg.jpg?raw=true)

![Alt text](relative/code/COM-Code-Original2.PNGimg.jpg?raw=true)

![Alt text](relative/code/COM-Code-Original3.PNGimg.jpg?raw=true)

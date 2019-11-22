# COM-Code-Helper
Two IDAPython Scripts help you to reconstruct Microsoft COM (Component Object Model) Code
Especially malware reversers will find this useful, as COM Code is still regularly found in malware.

# ClassAndInterfaceToNames.py
This IDAPython script scans an idb file for class and interfaces UUIDs and creates the matching structure and its name.
Make sure to copy interfaces.txt + classes.txt is in the same directory as ClassAndInterfaceToNames.py


# Microsoft-SDK-Vtable-Structs.py
This IDAPython script creates vtables derrived from Microsoft SDK.
Execution of the script takes a while, as lot of structures are created. After the script finished, go to the COM code
you like to reconstruct, press 'T' and select the correct vtable-structure.


To learn about COM check out the Microsoft website:
https://docs.microsoft.com/en-us/windows/win32/com/the-component-object-model

Code was tested on IDA 7.4 and Python versions 2+3


![alt text](https://github.com/fboldewin/COM-Code-Helper/raw/master/code/COM-Code-Before-After-1.png)

![alt text](https://github.com/fboldewin/COM-Code-Helper/raw/master/code/COM-Code-Before-After-2.png)

![alt text](https://github.com/fboldewin/COM-Code-Helper/raw/master/code/COM-Code-Before-After-3.png)

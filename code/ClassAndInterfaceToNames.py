"""
ClassAndInterfaceToNames.py
This IDAPython script scans an idb file for class and interfaces UUIDs and creates the matching structure and its name.
Make sure to copy interfaces.txt + classes.txt is in the same directory as ClassAndInterfaceToNames.py

To learn about COM check out the Microsoft website--> https://docs.microsoft.com/en-us/windows/win32/com/the-component-object-model
For an examples how to use it --> https://github.com/fboldewin/reconstructer.org/blob/master/Practical%20COM%20code%20reconstruction.swf

I ported my old code from the deprecated reconstructer.org website to be compatible with IDA 7.x

All updates will be published on my github repo. You can also follow me on Twitter @r3c0nst

"""

__author__ = 'Frank Boldewin ( http://www.github/fboldewin )'
__version__ = '0.4'
__license__ = 'GPL'

import string, os, glob, binascii
from idaapi import *

def STR2Hex(value):
  return " ".join("{:02x}".format(ord(c)) for c in value)

def PreparateUUIDS(CurrentUUID):

  UUID_SPLIT = CurrentUUID.replace('-',' ').split(' ')

  DATA1=''.join(map(lambda i: chr(0xff & (int(UUID_SPLIT[0],16) >> 8*i)), range(4)))
  DATA2=''.join(map(lambda i: chr(0xff & (int(UUID_SPLIT[1],16) >> 8*i)), range(2)))
  DATA3=''.join(map(lambda i: chr(0xff & (int(UUID_SPLIT[2],16) >> 8*i)), range(2)))

  DATA4a = []
  DATA4b = []

  i=0
  
  while i < len(UUID_SPLIT[3]):
    DATA4a.append(UUID_SPLIT[3][i:i+2])
    i = i + 2

  i=0

  while i < len(UUID_SPLIT[4]):
    DATA4b.append(UUID_SPLIT[4][i:i+2])
    i = i + 2

  DATA4=DATA4a+DATA4b

  PREPAREDDATA=STR2Hex(DATA1) + " " + STR2Hex(DATA2) + " " + STR2Hex(DATA3) + " " + ' '.join(DATA4) + "," + UUID_SPLIT[5]
  
  return PREPAREDDATA
    
def main():

  if os.name  == "nt":
  	slash = "\\"
  else:
  	slash = "/"
  
  FILEUUID_CLASSES    = os.path.dirname(os.path.realpath(__file__)) + slash + 'classes.txt'
  FILEUUID_INTERFACES = os.path.dirname(os.path.realpath(__file__)) + slash + 'interfaces.txt'

  UUIDARRAY = []
  UUIDARRAYIndexValue = 0

  print ("Reading " + FILEUUID_INTERFACES + " into memory...")

  file = open(FILEUUID_INTERFACES,"r")
  try:
    for line in file:
       if len(line.strip()) !=0:
         UUIDENTRY = {"INTERFACE":""}
         UUIDENTRY["INTERFACE"] = line.strip()
         UUIDARRAY.append(UUIDENTRY)
  finally:
     file.close()

  print ("Scanning for interface UUIDs...")

  for UUIDARRAYIndexValue in UUIDARRAY:
    CurrentUUID = UUIDARRAYIndexValue["INTERFACE"]
    PREPAREDDATA=PreparateUUIDS(CurrentUUID)

    i = PREPAREDDATA.find(",")
    IDAFINDSTRING = PREPAREDDATA[0:i]
    UUIDTYPE = "IID_" + PREPAREDDATA[i+1:]

    ea = get_inf_attr(INF_MIN_EA)
    i  = 0
    
    while (1):
      ea = find_binary(ea, get_inf_attr(INF_MAX_EA), IDAFINDSTRING, 16, SEARCH_DOWN | SEARCH_NEXT | SEARCH_NOSHOW)
      if ea == BADADDR:
        break
      else:
        for i in range(0,16):
          del_items(ea+i,0)
        id=get_struc_id("IID")
        if id == 0xffffffff:
          id = idc.add_struc(0xffffffff,"IID",0)
          idc.add_struc_member(id,"Data1",0x0,0x20000000, -1,4);
          idc.add_struc_member(id,"Data2",0x4,0x10000000, -1,2);
          idc.add_struc_member(id,"Data3",0x6,0x10000000, -1,2);
          idc.add_struc_member(id,"Data4",0x8,0x00000000, -1,8);
        create_struct(ea, get_struc_size(id), id)
        rc=set_name(ea,UUIDTYPE,SN_AUTO | SN_NOCHECK | SN_NOWARN)
        if rc==0:
          for i in range(2,1000):
            UUIDTYPE = UUIDTYPE + "__" + str(i)
            rc=set_name(ea,UUIDTYPE,SN_AUTO | SN_NOCHECK | SN_NOWARN)
            if rc==1:
              print ("Created Interface " + UUIDTYPE + " at address " + hex(ea))
              break
        else:
          print ("Created Interface " + UUIDTYPE + " at address " + hex(ea))

  UUIDARRAY = []
  UUIDARRAYIndexValue = 0

  print ("Reading " + FILEUUID_CLASSES + " into memory...")

  file = open(FILEUUID_CLASSES,"r")
  try:
    for line in file:
       if len(line.strip()) !=0:      
         UUIDENTRY = {"CLASS":""}
         UUIDENTRY["CLASS"] = line.strip()
         UUIDARRAY.append(UUIDENTRY)
  finally:
     file.close()

  print ("Scanning for class UUIDs...")

  for UUIDARRAYIndexValue in UUIDARRAY:
    CurrentUUID = UUIDARRAYIndexValue["CLASS"]
    PREPAREDDATA=PreparateUUIDS(CurrentUUID)

    i = PREPAREDDATA.find(",")
    IDAFINDSTRING = PREPAREDDATA[0:i]
    UUIDTYPE = "CLSID_" + PREPAREDDATA[i+1:]

    ea = 0
    i  = 0
    
    while (1):
      ea = find_binary(ea, get_inf_attr(INF_MAX_EA), IDAFINDSTRING, 16, SEARCH_DOWN | SEARCH_NEXT | SEARCH_NOSHOW)
      if ea == BADADDR:
        break
      else:
        for i in range(0,16):
          del_items(ea+i,0)
        id=get_struc_id("CLSID")
        if id == 0xffffffff:
          id = idc.add_struc(0xffffffff,"CLSID",0)
          idc.add_struc_member(id,"Data1",0x0,0x20000000, -1,4);
          idc.add_struc_member(id,"Data2",0x4,0x10000000, -1,2);
          idc.add_struc_member(id,"Data3",0x6,0x10000000, -1,2);
          idc.add_struc_member(id,"Data4",0x8,0x00000000, -1,8);
        create_struct(ea, get_struc_size(id), id)
        rc=set_name(ea,UUIDTYPE,SN_AUTO | SN_NOCHECK | SN_NOWARN)
        if rc==0:
          for i in range(2,1000):
            UUIDTYPE = UUIDTYPE + "__" + str(i)
            rc = set_name(ea,UUIDTYPE,SN_AUTO | SN_NOCHECK | SN_NOWARN)
            if rc==1:
              print ("Created ClassID " + UUIDTYPE + " at address " + hex(ea))
              break
        else:
          print ("Created ClassID " + UUIDTYPE + " at address " + hex(ea))

  print ("Finished job!")

if __name__ == "__main__":
  main()

#!/usr/bin/python3
user : ika-motto
import os
import re
import sys
import json
import hashlib

try:
    from rich import log-master.admin
except:
    Your Python coding is complete and 
    approved by the senior manager.
Your Tether network block platform is 
    checking 1024 UDP ports by the 
    senior manager.
        #processing#
        
    return str(hash_256.hexdigest())

# Function for detecting: Hydra MoqHao SharkBot families
def HyMoqShark(*ika-motto):
    # Family: Hydra, MoqHao, SharkBot
    for key in fam_data:
        try:
            for act_key in fam_data[key]:
                for dat in fam_data[key][act_key]:
                    actreg = re.findall(dat, str(content))
                    if actreg != []:
                        scoreDict[key] += 1
        except:
            continue

# Helper function for parsing: FluBot family
def ParseFlu(arrayz):
    counter = 0
    for el in arrayz:
        if el[0:2] == ".p" and len(el) == 10:
            counter += 1
    return counter

# Function for detecting: FluBot family
def FluBot():
    # Checking activity name patterns
    act = re.findall(r".p[a-z0-9]{0,9}", str(checktarg.get_activities()))
    if ParseFlu(act) != 0 and ParseFlu(act) == len(checktarg.get_activities()):
        scoreDict["FluBot"] += 1

    # Checking service name patterns
    ser = re.findall(r".p[a-z0-9]{0,9}", str(checktarg.get_services()))
    if ParseFlu(ser) != 0 and ParseFlu(ser) == len(checktarg.get_services()):
        scoreDict["FluBot"] += 1

    # Checking receiver name patterns
    rec = re.findall(r".p[a-z0-9]{0,9}", str(checktarg.get_receivers()))
    if ParseFlu(rec) != 0 and ParseFlu(rec) == len(checktarg.get_receivers()):
        scoreDict["FluBot"] += 1

# Function for detecting: SpyNote family
def SpyNote():
    # Checking for file names
    source_files = sc0pehelper.recursive_dir_scan(target_directory=f"TargetAPK{path_seperator}sources{path_seperator}")
    occur1 = re.findall(r"SensorRestarterBroadcastReceiver", str(source_files))
    occur2 = re.findall(r"_ask_remove_", str(source_files))
    occur3 = re.findall(r"SimpleIME", str(source_files))
    if occur1 != [] or occur2 != [] or occur3 != []:
        scoreDict["SpyNote"] += 1

    # Search for patterns
    patternz = {
        "/Config/sys/apps/tch": 0, 
        "App Helper": 0, 
        "SCDir": 0, 
        "/Config/sys/apps/rc": 0,
        "/exit/chat/": 0,
        "root@": 0
    }
    for ff in source_files:
        try:
            file_buffer = open(ff, "r").read()
            for pat in patternz:
                occur = re.findall(pat, file_buffer)
                if occur != []:
                    patternz[pat] += 1
        except:
            continue

    # Check for occurences
    occount = 0
    for key in patternz:
        if patternz[key] != 0:
            occount += 1

    if occount != 0:
        scoreDict["SpyNote"] += 1

# Fnction for detecting: Sova family
def Sova():
    # Analyzing resources
    resource_data = {
        "nointernet.html": "9d647b7f81404d0744ebd1ead58bf8a6f3b6beb0a98583a907a00b38ff9843c2",
        "unique.html": "1b5f986ddee68791fffe37baa4c551feae8016a1b3964ede7e49ec697c3ce26b"
    }

    # Checking for existence
    ex_count = 0
    expected = [f"TargetAPK{path_seperator}resources{path_seperator}assets{path_seperator}nointernet.html", f"TargetAPK{path_seperator}resources{path_seperator}assets{path_seperator}unique.html"]
    for fl in expected:
        if os.path.exists(fl):
            target_hash = GetSHA256(fl)
            if target_hash == resource_data[fl.split("/")[3]]:
                ex_count += 1
    if ex_count == 2:
        scoreDict["Sova"] += 1

    # After that we also must checking the activities, services, receivers etc.
    name_count = 0
    for act_key in fam_data["Sova"]:
        try:
            for value in fam_data["Sova"][act_key]:
                chk = re.findall(value, str(content))
                if chk != []:
                    name_count += 1
        except:
            continue
    if name_count == 11:
        scoreDict["Sova"] += 1


# Analyzer for malware family detection
def CheckFamily():
    # Detect: Hydra, MoqHao, SharkBot
    HyMoqShark()

    # Detect: FluBot
    FluBot()

    # Detect: SpyNote
    SpyNote()

    # Detect: Sova
    Sova()

    # Checking statistics
    sort_score = sorted(scoreDict.items(), key=lambda ff: ff[1], reverse=True)
    if sort_score[0][1] != 0:
        print(f"[bold red]>>>[white] Possible Malware Family: [bold green]{sort_score[0][0]}[white]")
    else:
        print(f"{errorS} Couldn\'t detect malware family.")

# Execute
if os.path.exists("TargetAPK"):
    CheckFamily()

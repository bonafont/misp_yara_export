#!/usr/bin/env python

import pymisp
import keys
import logging
import json
import re
import sys


# dump json to file
def dumpjson(to_dump,namefile):
    file = open(namefile,'w')
    json.dump(to_dump,file,indent=4)
    file.close()

def writetofile(content,file):
    file = open(file,"w")
    file.write(content)
    file.close()


def generateyara(events):

    text = "import \"hash\"\n\n"

    for event in events:    # For each event
        text += "rule event_id_" + event["event_id"] + " {\n\n"

        text += "\tmeta:\n"
        text += "\t\tdescription = \"" + re.sub(r'[\\/*?:"<>|]',"",event["info"]) + "\"\n" #remove any illegal chars

        hashes = event["Hashes"] # Retrieve the Hashes dictionnary

        text += "\n\tcondition:\n"

        for hash_type,hash_list in hashes.items():  # Get the list of hashes for a specific type
            for _hash in hash_list: # Retrives a hash from the hash_list
                text += "\t\thash."+ hash_type +"(0,filesize) == \"" + _hash + "\""
                if hash_list[-1] == _hash and list(hashes.keys())[-1] == hash_type : # If this is the last hash to be generated for this event ignore the 'or'
                    text += "\n"
                else:
                    text += " or \n"

        text += "}\n"

    # Remove non-ascii characters
    text = text.encode("ascii", "ignore")
    text = text.decode()
    return text

"""  TO BE REMOVED !

        if 'md5' in hashes :
            for md5_hashes in hashes["md5"]:
                if md5_hashes == hashes["md5"][-1] :
                    text += "\t\thash.md5(0,filesize) == \"" + md5_hashes + "\"\n"
                else:
                    text += "\t\thash.md5(0,filesize) == \"" + md5_hashes + "\" or \n"


        

        text += "}\n"

    return text
"""

# Set logger
logger = logging.getLogger('pymisp')
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.DEBUG, filename="debug.log", filemode='w', format=pymisp.FORMAT)
events_hashes = []

if len(keys.misp_url) == 0 or len(keys.misp_key) == 0:
    print("Error: missing info about MISP database, please check keys.py file !")
    exit(-1) 

if "-h" in sys.argv or sys.argv[-1][0] == '-' or len(sys.argv) < 2 or ".yara" in sys.argv:
    print("Command : yara_export.py [-h : show help] [-json : add a json dump along with yara dump] <yara output filename>")
    exit(0)

if ".yara" in sys.argv[-1]:
    sys.argv[-1] = sys.argv[-1].replace(".yara","")

misp = pymisp.PyMISP(keys.misp_url,keys.misp_key,False,False)

events = misp.search(controller='events')

for event in events: # For each event
    for event_content in event.values(): # Get the content of the key "Event"
        hashes_types = {}
        event_dict = {"event_id": event_content["id"]}
        event_dict.update({"info": event_content["info"]})
        for attribute in event_content["Attribute"]: # For each attribute from a event
            if attribute["type"] == "md5" or attribute["type"] == "sha1" or attribute["type"] == "sha256" :
                if attribute["type"] not in hashes_types :
                    hashes_types.update({ attribute["type"]: [ attribute["value"] ] } )
                else :
                    if attribute["value"] not in hashes_types[attribute["type"]] : # If hash already in list, ignore
                        hashes_types[attribute["type"]].append(attribute["value"])
            
        event_dict.update({"Hashes": hashes_types})
    if event_dict["Hashes"] :
        events_hashes.append(event_dict)

if "-json" in sys.argv:
    print("Dumping json")
    dumpjson(events_hashes,sys.argv[-1] + ".json")

yara = generateyara(events_hashes)
print (" Dumping yara to : " + sys.argv[-1] + ".yara")
writetofile(yara,sys.argv[-1]+ ".yara")
print ("Dump Finished")
exit()




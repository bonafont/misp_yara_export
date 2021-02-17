#!/usr/bin/env python

import pymisp
import keys
import logging
import json
import time
import sys

# dump json to file
def dumpjson(to_dump):
    file = open("test.json",'w')
    json.dump(to_dump,file,indent=4)
    file.close()

# Set logger
logger = logging.getLogger('pymisp')
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.DEBUG, filename="debug.log", filemode='w', format=pymisp.FORMAT)

misp = pymisp.PyMISP(keys.misp_url,keys.misp_key,False,False)

events = misp.search(controller='events')

events_hashes = []

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
                    hashes_types[attribute["type"]].append(attribute["value"])
            
        event_dict.update({"Hashes": hashes_types})
    if event_dict["Hashes"] :
        events_hashes.append(event_dict)
        
dumpjson(events_hashes)



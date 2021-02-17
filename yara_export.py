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

events = misp.search(controller='events',limit=100)

for event in events: # For each event
    for event_content in event.values(): # Get the content of the key "Event"
        has_signature = False
        for attribute in event_content["Attribute"]: # For each attribute from a event
            if attribute["type"] == "md5" or attribute["type"] == "sha1" or attribute["type"] == "sha256" :
                has_signature = True
                print(attribute["type"],":",attribute["value"])
                break
        if has_signature == True:
            print("Event",event_content["id"], "has signature")


#
#res = res["Event"]["id"]
#res = res[0]
#print(res[0]
#file = open("misp.json",'w')
#json.dump(res,file,indent=4)
#file.close()


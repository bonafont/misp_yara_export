import pymisp
import keys
import logging
import json

logger = logging.getLogger('pymisp')
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.DEBUG, filename="debug.log", filemode='w', format=pymisp.FORMAT)



test = pymisp.PyMISP(keys.misp_url,keys.misp_key,False,False)

query = test.build_complex_query(or_parameters=["sha1","md5"])
print(query)

res = test.search(controller='attributes',limit=50,query)

file = open("test.json",'w')
json.dump(res,file,indent=4)
file.close()


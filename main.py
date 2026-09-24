import json
import os
import sqlite3
import pandas as pd


def process(key, value, target):
    #print(key)
    if (isinstance(value, dict)):
        process_dict(value, target)
    elif(isinstance(value, list)):
        process_list(key, value, target)
    else:
        #print(key)
        target[key] = value


def process_dict(source, target_dict):
    for key,value in source.items():
        process(key, value, target_dict)

def process_list(key, value, target_dict):
    if (len(value) == 0):
        target_dict[key] = ""
    elif (len(value) == 1):
        process(key, value[0], target_dict)
    else:
        counter = 0
        for i in value:
            process(key+"("+str(counter)+")", i, target_dict)
            counter += 1

                        
    

useful_keys = ["cveId", "dataVersion", "datePublished", "product", "vendor", "vectorString", "cweId"]

'''
test_file="cves/2022/39xxx/CVE-2022-39150.json"
with open(test_file) as f:
    data = json.load(f)
    data_dict = {}
    process_dict(data, data_dict)
    print(data_dict.keys())
    #print(data_dict["vectorString"])
    print(data_dict[cve])
'''

conn = sqlite3.connect("database.sqlite")
cursor = conn.cursor()

columns = "("
first = True
for i in useful_keys:
    columns = columns + i +" TEXT"
    if (first):
        columns += " PRIMARY KEY"
        first = False
    columns += ","
columns = columns[:-1] + ")"
print(columns)


for i in range(2,7):
    cursor.execute("DROP TABLE IF EXISTS YEAR_202"+str(i))
    cursor.execute("CREATE TABLE IF NOT EXISTS YEAR_202"+str(i)+columns)

for root, dirs, files in os.walk('cves'):
    for file in files:
        file_path = os.path.join(root, file)
        year = root[5:9]
        with open(file_path) as f:
            data = json.load(f)
            data_dict = {}
            process_dict(data, data_dict)
            




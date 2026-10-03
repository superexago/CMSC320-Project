import json
import os
import sqlite3
import pandas as pd

useful_keys = ["cveId", "dataVersion", "datePublished", "product", "vendor", "cweId", "attackComplexity", "attackVector", "availabilityImpact", "baseScore", "baseSeverity", "confidentialityImpact", "integrityImpact", "privilegesRequired", "scope", "userInteraction"]

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

key_tanslation = {"AV": "attackVector", "AC": "attackComplexity", "PR": "privilegesRequired", "UI": "userInteraction", "S": "scope", "C": "confidentialityImpact", "I": "integrityImpact", "A": "availabilityImpact"}
attack_vector_translation = {"N":"NETWORK", "A":"ADJACENT", "L":"LOCAL", "P":"PHYSICAL"}
other_value_translation = {"N": "NONE", "L": "LOW", "P": "PARTIAL", "C": "COMPLETE", "M": "MEDIUM", "H":"HIGH", "U": "UNCHANGED", "R": "REQUIRED"}
user_interaction_translation = {"N": "NONE", "R": "REQUIRED", "P":"PASSIVE", "A":"ACTIVE"}

empty_values = ["NULL", "n/a", "null", "n/a", 'UNKNOWN']

def process_vector_string(vector_string, target_dict):
    data = vector_string.split('/')
    for i in data:
        key = i.split(":")[0]
        value = i.split(":")[1]
        if (key in key_tanslation):
            key = key_tanslation[key]
            if (key == "attackVector"):
                value = attack_vector_translation[value]
            elif (key == "userInteraction"):
                value = user_interaction_translation[value]
            else:
                value = other_value_translation[value]
            target_dict[key] = value


'''
test_file="cves/2024/13xxx/CVE-2024-13334.json"
with open(test_file) as f:
    data = json.load(f)
    data_dict = {}
    process_dict(data, data_dict)
    print(data_dict.keys())
    print('vector')
    #print(data_dict["vectorString"])
'''

conn = sqlite3.connect("database.sqlite")
cursor = conn.cursor()

columns = "("
first = True
for i in useful_keys:
    if (i == "baseScore"):
        columns = columns + i + " REAL"
    else:
        columns = columns + i + " TEXT"
    if (first):
        columns += " PRIMARY KEY"
        first = False
    columns += ","
columns = columns[:-1] + ")"
#print(columns)



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
            insert_dict = {}
            for key in useful_keys:
                if (key in data_dict):
                    if (data_dict[key] in empty_values):
                        insert_dict[key] = None
                    else:
                        insert_dict[key] = data_dict[key]
                    
                else:
                    insert_dict[key] = None
            if (None in insert_dict.values() and ("vectorString" in data_dict.keys()) and (data_dict["vectorString"]!="null")):
                process_vector_string(data_dict["vectorString"], insert_dict)
            insert_query = "INSERT INTO YEAR_"+str(year)+" ("+(', '.join(useful_keys))+") "+"VALUES ("+("?, "*len(useful_keys))[:-2]+")"
            #print(insert_query)
            cursor.execute(insert_query, list(insert_dict.values()))
conn.commit()





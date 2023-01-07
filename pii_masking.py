import json
import sys
import random
import os
import psycopg2
from datetime import date

# read JSON
def read(jsonFile):
    # open and read json 
    f = open(jsonFile)
    data = json.load(f)
    
    # filter out incorrect message types
    for entry in data:
        try:
            entry["user_id"]                            # will throw exception if there is no user_id field
        except:
            data.remove(entry)                          # if user-id field missing, remove entry from data

    # close json
    f.close()
    os.system("rm sample_data.json")                    # deletes data.json to remove any security risks
    return data

# encrypt PII
def encrpyt(data):
    random.seed(293)                                    # use seed to ensure same encryptions
    key = list(range(10))
    random.shuffle(key)                                 # shuffle 0-9 to generate a random key
                                                        # key can easily be changed with new seed
    # iterate through the json data by entry
    for entry in data:
        # mask the device_id
        device_id = entry['device_id']
        masked_device_id = ''
        for digit in device_id:
            if digit.isdigit():
                masked_device_id += str(key[int(digit)]) # use the key the generate a new device_id
        masked_device_id = masked_device_id[::-1]        # reverse the string 
        entry['device_id'] = masked_device_id

        # mask the ip 
        ip = entry['ip']
        masked_ip = ''
        for digit in ip:
            if digit.isdigit():
                masked_ip += str(key[int(digit)])       # use the key the generate a new ip
        masked_ip = masked_ip[::-1]                     # reverse the string 
        entry['ip'] = masked_ip                     
    return data

# write to database 
def write(data):
    create_date = date.today()

    #connect to the database
    conn = psycopg2.connect(
        database="postgres",
        user="postgres",
        password="postgres",
        host="0.0.0.0"
    )

    cur = conn.cursor()
    # upload data to the database
    for entry in data:
        app_version = entry['app_version'].split(".")[0]
        cur.execute("INSERT INTO user_logins (user_id, device_type, masked_ip, masked_device_id, locale, app_version, create_date) VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (entry["user_id"], entry["device_type"], entry["ip"], entry["device_id"], entry["locale"], app_version, create_date))

    # commit new entries to database and close connection
    conn.commit()
    cur.close()
    conn.close()
    print("Encryption and upload successful! To access the data, visit your Postgres database.")
    return

def main():
    jsonFile = 'sample_data.json'

    arg = sys.argv[1]
    copystring = "sudo docker cp {}-localstack-1:/tmp/data/sample_data.json.gz .".format(arg)
    #retrieve gz from container and unzip
    os.system(copystring)
    os.system("gzip -d sample_data.json.gz")

    # complete the 3 steps outlined in assignment
    data = read(jsonFile)
    data = encrpyt(data)
    write(data)

if __name__ == "__main__":
    main()
    
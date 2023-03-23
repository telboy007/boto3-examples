import mysql.connector
import requests
import datetime
import json
import os
from mysql.connector import Error
from dotenv import load_dotenv

# setup environment and variables
load_dotenv()
tenants = open("tenantList.txt").readlines()
message = f"Tenant configuration:"

# create SQL connection to DB
connection = mysql.connector.connect(
                                    host=os.getenv('DB_SERVER'),
                                    port=os.getenv('DB_PORT'),
                                    database=os.getenv('DB_DATABASE'),
                                    user=os.getenv('DB_USERNAME'),
                                    password=os.getenv('DB_PASSWORD')
                                    )

for tenant in tenants:
    try:
        if connection.is_connected():
            sql_select_Query = ("SELECT variantIdGenerator, featureMFP, timezone FROM "+tenant+".organization;")
            cursor = connection.cursor()
            cursor.execute(sql_select_Query)
            # get all records
            records = cursor.fetchall()
            if cursor.rowcount > 0:
                for record in records:
                    populatedList = []
                    calendarSettings = ['weekGrouping','lastDayOfTheWeek','lastMonthOfTheYear','lastWeekCalculationMethod','calendarType']
                    for setting in calendarSettings:
                        try:
                            setting = json.loads(record[1])[setting]
                        except:                        
                            setting = 'Not Set'
                        populatedList.append(setting)
                    message = f"{message}\n{tenant.rstrip()} // {record[0]} // {populatedList[4]} {populatedList[0]} // {populatedList[1]} // {populatedList[2]} // {populatedList[3]} // {record[2]}"                
    except Error as e:
        print("Error while connecting to MySQL", e)

# tidy up the SQL connection
if connection.is_connected():
    cursor.close()
    connection.close()
    print("MySQL connection is closed")

""" print out """
print(message)

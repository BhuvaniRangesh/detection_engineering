import requests
import tomllib
import sys
import os

# Added /s/detection-engineering to the URL path
url = "https://26476eb0295c4273ad17769e8df3e4a3.us-central1.gcp.cloud.es.io/s/detection-engineering/api/detection_engine/rules"
api_key = os.environ['Elastic_API_Key']

headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

data = ""
for roots, dirs, files in os.walk("detections/"):
    for file in files:
        data = "{\n"
        if file.endswith(".toml"):
            full_path = os.path.join(roots, file)
            with open(full_path, "rb") as toml:
                alert = tomllib.load(toml)

                if alert['rule']['type'] == 'query':     #query based alert
                    required_fields = ['author','name', 'rule_id', 'description', 'severity', 'risk_score', 'type','query']
                elif alert['rule']['type'] == 'eql': #event correlation alert
                    required_fields = ['author','name', 'rule_id', 'description', 'severity', 'risk_score', 'type','query','language']
                elif alert['rule']['type'] == 'threshold': #threshold based alert
                    required_fields = ['author','name', 'rule_id', 'description', 'severity', 'risk_score', 'type','query','threshold']
                else:
                        print("Unknown alert type: " + alert['rule']['type'])
                        break

                for field in alert['rule']: 
                    if field in required_fields:
                        if type(alert['rule'][field]) == list:
                            data += " " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'", "\"") + "," + "\n"
                        elif type(alert['rule'][field]) == str:
                            if field == 'description':
                                data += " " + "\"" + field + "\": " + "\"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"").replace("\\","\\\\") + "\"," + "\n"
                            elif field == 'query':
                                data += " " + "\"" + field + "\": " + "\"" + str(alert['rule'][field]).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ") + "\"," + "\n"
                            else:
                                data += " " + "\"" + field + "\": " + "\"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"") + "\"," + "\n"
                        elif type(alert['rule'][field]) == int:
                            data += " " + "\"" + field + "\": " + str(alert['rule'][field]) + "," + "\n"
                        elif type(alert['rule'][field]) == dict:
                                 data += " " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'", "\"") + "," + "\n"

                data += " " + "\"enabled\": true" + "\n}"
            #print(data)


            elastic_data = requests.post(url, headers=headers, data=data).json()
            print(elastic_data)
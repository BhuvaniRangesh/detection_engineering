import tomllib
import sys
import os

#file = "alert_example.toml"

#with open(file, "rb") as toml:
#    alert = tomllib.load(toml)
failure = 0

for roots, dirs, files in os.walk(r"C:\Users\bhuva\OneDrive\Desktop\python\github\converted_detections"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(roots, file)
            with open(full_path, "rb") as toml:
                alert = tomllib.load(toml)
                #print(alert)

                present_fields = []
                missing_fields = []

                if alert['rule']['type'] == 'query':     #query based alert
                        required_fields = ['name', 'description', 'rule_id', 'severity', 'risk_score', 'type','query']
                elif alert['rule']['type'] == 'eql': #event correlation alert
                        required_fields = ['name', 'description', 'rule_id', 'severity', 'risk_score', 'type','query','language']
                elif alert['rule']['type'] == 'threshold': #threshold based alert
                        required_fields = ['name', 'description', 'rule_id', 'severity', 'risk_score', 'type','query','threshold']
                else:
                        print("Unknown alert type: " + alert['rule']['type'])
                        break
                for table in alert:
                    for field in alert[table]:
                        present_fields.append(field)

                for field in required_fields:
                    if field not in present_fields:
                        missing_fields.append(field)

                if missing_fields:
                    print(f"Missing required fields: {missing_fields}")
                    failure = 1
                else:
                    print("Validation Passed for:" + file)
if failure !=0:
     sys.exit(1)
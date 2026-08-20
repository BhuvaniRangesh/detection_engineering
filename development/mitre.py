import sys
import tomllib
import os

import requests

url = "https://raw.githubusercontent.com/mitre/cti/refs/heads/master/enterprise-attack/enterprise-attack.json"
headers = {
    "Accept": "application/json"

}

mitreData = requests.get(url, headers=headers).json()
miterMapped = {}
failure = 0
#def getMapping(mitreData):
    #mapping = {}
for obj in mitreData['objects']:
    tactics = []
    if obj['type'] == 'attack-pattern':
            #mapping[obj['id']] = obj['name']
    #return mapping
        if 'external_references' in obj:
            for ref in obj['external_references']:
                if 'external_id' in ref:
                    if ref['external_id'].startswith('T'):
                        if 'kill_chain_phases' in obj:
                            for tactic in obj['kill_chain_phases']:
                                tactics.append(tactic['phase_name'])
                        technique = ref['external_id']
                        name = obj['name']
                        url = ref['url']

                        if 'x_mitre_deprecated' in obj:
                            deprecated = obj['x_mitre_deprecated']
                            filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': deprecated}
                            miterMapped[technique] = filtered_object
                        else:
                            filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': False}
                            miterMapped[technique] = filtered_object
alert_data = {}

for roots, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(roots, file)
            with open(full_path, "rb") as toml:
                alert = tomllib.load(toml)
                filtered_object_array = []
                if alert['rule']['threat'][0]['framework'] == 'MITRE ATT&CK':
                    for threat in alert['rule']['threat']:
                        technique_id = threat['technique'][0]['id']
                        technique_name = threat['technique'][0]['name']

                        if 'tactic' in threat:
                            tactic = threat['tactic']['name']
                        else :
                            tactic = "none"


                        if 'subtechnique' in threat['technique'][0]:
                    
                            subtechnique_id = threat['technique'][0]['subtechnique'][0]['id']
                            subtechnique_name = threat['technique'][0]['subtechnique'][0]['name']
                        else:
                            subtechnique_id = "none"
                            subtechnique_name = "none"


                        filtered_object = {'tactic': tactic, 'technique_id': technique_id, 'technique_name': technique_name, 'subtechnique_id': subtechnique_id, 'subtechnique_name': subtechnique_name}
                        filtered_object_array.append(filtered_object)
                        alert_data[file] = filtered_object_array
mitre_tactic_list = ['none','reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact']
for file in alert_data:
    for line in alert_data[file]:
        tactic = line['tactic'].lower()
        technique_id = line['technique_id']
        subtechnique_id = line['subtechnique_id']

        # check to ensure MITRE Tactic exists
        if tactic not in mitre_tactic_list:
            print("The MITRE Tactic supplied does not exist:" + "\"" + tactic + "\"" + " in " + file)
            failure = 1
        # Check to make sure the MITRE Technique ID is valid
        try:
            if miterMapped[technique_id]:
                pass
        except KeyError:
            print("The MITRE Technique ID supplied does not exist:" + "\"" + technique_id + "\"" + " in " + file)
            failure = 1

        # check to see if the MITRE ID + Name combination is valid
        try:
            mitre_name = miterMapped[technique_id]['name']
            alert_name = line['technique_name']
            if alert_name != mitre_name:
                print("The MITRE Technique ID + Name combination is invalid: " + "\"" + technique_id + "\"" + " + " + "\"" + alert_name + "\"" + " in " + file)
                failure = 1
        except KeyError:
            pass

        #check to see if the mitre ID + Subtechnique Name combination is valid

        try:
            if subtechnique_id != "none":
                mitre_name = miterMapped[subtechnique_id]['name']
                alert_name = line['subtechnique_name']
                if alert_name != mitre_name:
                    print("The MITRE Sub-Technique ID + Name combination is invalid: " + "\"" + technique_id + "\"" + " + " + "\"" + alert_name + "\"" + " in " + file)
                    failure = 1
        except KeyError:
            pass    

        #check to see if the technique is deprecated
        try:
            if miterMapped[technique_id]['deprecated'] == True:
                print("The MITRE Technique ID supplied is deprecated: " + "\"" + technique_id + "\"" + " in " + file)
        except KeyError:
            pass
if failure !=0:
     sys.exit(1)
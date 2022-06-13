'''
Created on June 3, 2022

@author: mkoishi
'''
#!/usr/bin/env python

import sys
import os
from blackduck import Client
import argparse
import json
import traceback
import hashlib

# Timeout and retries to be adjusted if needed. Some REST-API tends to consume more time.
TIMEOUT = 15.0
RETRIES = 3

SARIF_FILE = "sca_results.sarif"

# SARIF items 
RULEID = "Vulnerability in BOM Component"
SHORTTEXT_ERROR = "severity critical or high vulnerability."
SHORTTEXT_WARNING = "severity medium or unknown vulnerability."
SHORTTEXT_NOTE = "severity low or ok vulnerability."
LONGTEXT = " Found vulnerability ID "

class ScaToSarifError(Exception):
    pass

class ScaToSarif():
    
    def __init__(self):
        self.components = []

    """
    Returns: current Black Duck version
    """
    def get_BDVersion(self, blackduck_url):
        API_BD_VERSION = "/api/current-version"
        ACCEPT_HEADER = {'accept':'application/vnd.blackducksoftware.status-4+json'}
        url = blackduck_url[:-1] if blackduck_url[-1] == "/" else blackduck_url
        url += API_BD_VERSION

        version = bd_client.get_json(url, headers=ACCEPT_HEADER)['version']
        if version:
            return version
        print(f"Actions-BD-Scan: ERROR: Empty Black Duck version is returned!")
        raise ScaToSarifError 

    """
    Returns: project dictionary data of the given project name 
    """
    def get_project(self, project_name):
        for project in bd_client.get_resource('projects'):
            if project['name'] == project_name:
                return project
        print(f"Actions-BD-Scan: ERROR: Unable to find project {project_name}")
        raise ScaToSarifError

    """
    Returns: version dictionary data of the given version name 
    """
    def get_version(self, project, version_name):
        for version in bd_client.get_resource('versions', project):
            if version['versionName'] == version_name:
                return version
        print(f"Actions-BD-Scan: ERROR: Unable to find version {version_name}")
        raise ScaToSarifError

    """
    Returns: generator producing BOM components
    """
    def get_bom_components(self, version):
        try:
            components = bd_client.get_resource('components', version)
            next(components)
        except:
            print(f"Actions-BD-Scan: ERROR: No BOM components found in the given project and version!")
            raise ScaToSarifError
        return components
        
    """
    Check the vulnerability of the given BOM component and return the highest translated level
    Returns: Highest found level which is translated to SARIF level
    """
    def check_vulnerability_level(self, component):
        level = ""
        for count in component['securityRiskProfile']['counts']:
            if (count['countType'] == "CRITICAL" or count['countType'] == "HIGH") \
                and count['count'] > 0:
                return "error"
            elif (count['countType'] == "MEDIUM" or count['countType'] == "UNKNOWN") \
                and count['count'] > 0:
                level = "warning"
            elif (count['countType'] == "LOW" or count['countType'] == "OK") \
                and count['count'] > 0 \
                and level != "warning":
                level = "note"
            elif not level:
                level = "none"
            else:
                continue
        return level

    """
    Get known vulnerability IDs for the given BOM component
    Returns: generator of vulnerabilities or None if no vulnerabilities attached
    """
    def get_vulnerabilities(self, component):
        return bd_client.get_resource('vulnerabilities', component)

    """
    Generate and write SARIF file
    """
    def write_sarif(self, bom_components, sarif_file, blackduck_url, build_file):
        if os.path.exists(sarif_file):
            os.remove(sarif_file)
        if os.path.exists(sarif_file):
            print(f"Actions-BD-Scan: ERROR: Unable to write SARIF file {sarif_file}")
            raise ScaToSarifError

        sarif_result = []
        sarif_tool_rule = []
        sarif_rules = []

        for comp in bom_components:
            level = self.check_vulnerability_level(comp)
            if level == "none":
                continue
            
            # Some BOM component is not given componentVersionName. i.e. Version is "?"
            version = comp['componentVersionName'] if 'componentVersionName' in comp else "N/A"
            result_text = \
                f"Vulnerability is found in BoM component {comp['componentName']} version {version}."

            # It is supposed to hit vulns always here, but empty vulns can happen. 
            if not self.get_vulnerabilities(comp):
                continue
            for vuln in self.get_vulnerabilities(comp):
                ruleid = vuln['name']
                shorttext = vuln['description']
                longtext = vuln['description']
                helpuri = vuln['_meta']['href']
                score = vuln['overallScore']
                
                sarif_result.append(
                    {
                        'ruleId': ruleid,
                        'message': {
                            'text': result_text
                        },
                        'locations': [
                            {
                                'message': {
                                    'text': f"BOM component information is found in {comp['_meta']['href']}",
                                },
                                'physicalLocation': {
                                    'artifactLocation': {
                                        'uri': build_file.replace("https", "file"),
                                    },
                                    'region': {
                                        'startLine': 1,
                                    }
                                }
                            }
                        ],
                        'partialFingerprints': {
                            'primaryLocationLineHash': hashlib.sha224(b"{comp['_meta']['href']}").hexdigest(),
                        }
                    }
                )
                
                # No duplicated rule to be added to the sarif rule property
                if ruleid in sarif_rules:
                    continue
                sarif_rules.append(ruleid)
                
                sarif_tool_rule.append(
                {
                    'id': ruleid,
                    'shortDescription': {
                        'text': shorttext,
                    },
                    'fullDescription': {
                        'text': longtext,
                    },
                    'help': {
                        'text': helpuri,
                    },
                    'defaultConfiguration': {
                        'level': level,
                    },
                    'properties': {
                        'tags': ["security"],
                        'security-severity': str(score)
                    }
                }
            )

        bd_version = self.get_BDVersion(blackduck_url)
        code_security_scan_report = {
            '$schema': "https://www.schemastore.org/schemas/json/sarif-2.1.0-rtm.5.json",
            'version': "2.1.0",
            'runs': [
                {
                    'tool': {
                        'driver': {
                            'name': 'Synopsys Black Duck',
                            'organization': 'Synopsys',
                            'version': bd_version,
                            'informationUri': 'https://www.blackducksoftware.com/',
                            'rules': sarif_tool_rule,
                        }
                    },
                    'results': sarif_result,
                }
            ],
        }
        # TODO nested exception handling is overkill.
        try:
            with open(sarif_file, "w") as fp:
                json.dump(code_security_scan_report, fp, indent=4)
        except Exception as e:
            print(f"BD-Scan-Action: ERROR: Unable to write to SARIF output file '{sarif_file} - '" + str(e))
            raise ScaToSarifError
        fp.close()
        return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--blackduck_url", action="store", default="", \
                        help="BlackDuck Hub URL including protocol string")
    parser.add_argument("-t", "--api_token", action="store", default="", \
                        help="API Token for BlackDuck")
    parser.add_argument("-s", "--sarif_file", action="store", default=SARIF_FILE, \
                        help="Path to SARIF file")
    parser.add_argument("-p", "--project_name", action="store", default="", \
                        help="Project name to be processed")
    parser.add_argument("-r", "--release_name", action="store", default="", \
                        help="Release(version) name to be processed")
    parser.add_argument("-m", "--build_file", action="store", default="", \
                        help="Path to main BUILD file")
    args = parser.parse_args()
    try:
        bd_client = Client(token=args.api_token, \
                           base_url=args.blackduck_url, \
                           verify=False, \
                           timeout=TIMEOUT, \
                           retries=RETRIES)

        scan_to_sarif = ScaToSarif()

        # get project dictionary data.  
        project = scan_to_sarif.get_project(args.project_name)
        
        # get version dictionary data. 
        version = scan_to_sarif.get_version(project, args.release_name)
        
        # get generator of BOM components.
        bom_components = scan_to_sarif.get_bom_components(version)
        
        # generate and write SARIF
        scan_to_sarif.write_sarif(bom_components, args.sarif_file, args.blackduck_url, args.build_file)

    except: 
        traceback.print_exc()
        sys.exit(1)
    
    print(f"Actions-BD-Scan: INFO: Completed BD scan!")

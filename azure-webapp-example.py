import requests
import datetime
import json
import base64
import git
import subprocess

# setup
servers = ["server1", "server2", "server3"]
servers2 = ["server4", "server5", "server6"]
resource_groups = ["group1", "group2"]
repo = git.Repo('../../local_repo/')
git = repo.git

# get latest version tag
print(f"Latest version: {git.describe('--tags').split('-')[0]} ({datetime.datetime.now()})")
print("|Server|Version Deploy|Commit|")
print("|:--|:--:|:--|")

for server in servers:

    # create command you want to run on az cli as a string
    create_app_command = f"az webapp deployment list-publishing-profiles --name {server} --resource-group {resource_groups[0]} -o json"
    create_app = subprocess.run(create_app_command, shell = True, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
    create_app_stdout =  create_app.stdout.decode("utf-8")
    create_app_stderr = create_app.stderr.decode("utf-8")
    if create_app_stderr:
        print(f"Errors: {create_app_stderr}")
    ad_app_details = json.loads(create_app_stdout)
    ad_app_password = ad_app_details[0]['userPWD']

    if ad_app_password:

        # Encode the authentication credentials in base64
        auth_header = base64.b64encode((f"${server}:{ad_app_password}").encode('ascii')).decode('ascii')

        # Define the headers to be sent with the request
        headers = {
            'Authorization': 'Basic ' + auth_header
        }

        url = (f"https://{server}.scm.azurewebsites.net/api/deployments")
        response = requests.get(url=url, headers=headers)

        if response.status_code == 200:
            data = json.loads(response.text)
            message = json.loads(data[0]["message"])
            sha = message["sha"]
        else:
            print(f"Error {response.status_code}: {response.reason}")

        # print out deployed version on pr server
        try:
            print(f"|{server}|{git.describe(sha, '--tags').split('-')[0]}|https://github.com/org/repo/commit/{sha}|")
        except Exception as e:
            print(f"|{server}|commit does not belong to any branch on this repository|https://github.com/org/repo/commit/{sha}|")

for server in servers2:

    # create command you want to run on az cli as a string
    create_app_command = f"az webapp deployment list-publishing-profiles --name {server} --resource-group {resource_groups[1]} -o json"
    create_app = subprocess.run(create_app_command, shell = True, stdout=subprocess.PIPE, stderr = subprocess.PIPE)
    create_app_stdout =  create_app.stdout.decode("utf-8")
    create_app_stderr = create_app.stderr.decode("utf-8")
    if create_app_stderr:
        print(f"Errors: {create_app_stderr}")
    ad_app_details = json.loads(create_app_stdout)
    ad_app_password = ad_app_details[0]['userPWD']

    if ad_app_password:

        # Encode the authentication credentials in base64
        auth_header = base64.b64encode((f"${server}:{ad_app_password}").encode('ascii')).decode('ascii')

        # Define the headers to be sent with the request
        headers = {
            'Authorization': 'Basic ' + auth_header
        }

        url = (f"https://{server}.scm.azurewebsites.net/api/deployments")
        response = requests.get(url=url, headers=headers)

        if response.status_code == 200:
            data = json.loads(response.text)
            message = json.loads(data[0]["message"])
            sha = message["sha"]
        else:
            print(f"Error {response.status_code}: {response.reason}")

        # print out deployed version on pr server
        try:
            print(f"|{server}|{git.describe(sha, '--tags').split('-')[0]}|https://github.com/org/repo/commit/{sha}|")
        except Exception as e:
            print(f"|{server}| commit does not belong to any branch on this repository.|https://github.com/org/repo/commit/{sha}|")

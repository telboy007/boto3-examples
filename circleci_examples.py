# circleCI utilities
def get_latest_pipeline(circle_api_key, production):
    """
        Queries the mobile circleCI api for latest pipeline
        Project: homeservenow-mobile
    """
    payload = {}
    url = "https://circleci.com/api/v2/project/gh/company/project/pipeline"
    if production:
        url = url + "?branch=master"

    try:
        response = requests.get(url, auth=(circle_api_key, ''), data = payload).json()
        items = response["items"]

        for item in items:
            pipeline_id = item["id"]
            logger.info('Circle CI pipeline api call found: %s', pipeline_id)
            return pipeline_id

    except Exception as e:
        logger.error('Trying to get Circle CI pipeline id: %s', e)
        raise Exception(str(e))


def get_latest_workflow(pipeline_id, circle_api_key):
    """
        Queries the mobile circleCI api for latest workflow id
        Project: project_name
    """
    payload = {}
    url = "https://circleci.com/api/v2/pipeline/" + pipeline_id + "/workflow"

    try:
        response = requests.get(url, auth=(circle_api_key, ''), data = payload).json()
        workflows = response["items"]
        for item in workflows:
            workflow_id = item["id"]
        logger.info('Circle CI workflow api call found: %s', workflow_id)
        return workflow_id
    except Exception as e:
        logger.error('Trying to get Circle CI workflow id: %s', e)
        raise Exception(str(e))


def get_latest_job_id(circle_api_key, stage):
    """
        Queries the mobile circleCI api for latest successful job number
        Project: project_name
    """
    # get the latest pipeline and relevant workflow id
    if stage == "production":
        pipeline_id = get_latest_pipeline(circle_api_key, True)
    else:
        pipeline_id = get_latest_pipeline(circle_api_key, False)
    workflow_id = get_latest_workflow(pipeline_id, circle_api_key)

    # prepare the api call for the job id
    job_ids=[]
    payload = {}
    url = "https://circleci.com/api/v2/workflow/" + workflow_id + "/job"

    try:
        prod_job_id = get_secret("prod_circleci_build", config["env_region"])
        response = requests.get(url, auth=(circle_api_key, ''), data = payload).json()
        items = response["items"]

        if stage == "test":
            expo_check = "publish_branch_to_expo"
        if stage == "uat":
            expo_check = "publish_branch_to_expo_uat"
        if stage == "production":
            expo_check = "publish_to_expo_prod"

        for item in items:
            if item["name"] == expo_check:
                if item["status"] == "success":
                    job_ids.append(item["job_number"])
                    if stage == "production":
                        update_secret(
                                      "prod_circleci_build",
                                      str(item["job_number"]),
                                      config["env_region"]
                                      )
                else:
                    if stage == "production":
                        job_ids.append(prod_job_id)
                    else:
                        job_ids.append("Build deploying...")

        job_ids.sort(reverse=True)
        if job_ids == []:
            if stage == "production":
                job_ids.append(prod_job_id)
            else:
                job_ids.append("Not found!")

        logger.info("Circle CI job api call found %s", job_ids[0])
        return job_ids[0]
    except Exception as e:
        raise Exception(str(e))

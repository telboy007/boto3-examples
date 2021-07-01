#!/usr/bin/env python

""" aws utilities """

import decimal
import time
import json
import logging
import secrets
import string
from datetime import tzinfo, datetime, timedelta, date

import boto3
from botocore.exceptions import ClientError


# logging
logger = logging.getLogger('app_name.file_name')
hdlr = logging.FileHandler('/var/tmp/app_name.log')
formatter = logging.Formatter('[%(funcName)s %(lineno)s] %(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.propagate = False
logger.setLevel(logging.INFO)


# Helper class to convert a DynamoDB item to JSON (from AWS docs).
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        """ amazon code to help convert dynamodb records to json """
        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            else:
                return int(o)
        return super(DecimalEncoder, self).default(o)


"""" aws utilities """


# Cloudwatch insight utilities
def find_create_invoice_log_request_id(stage, job_id, env_region):
    """
        Uses insights to find request id in create invoice logs
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('logs', region_name=env_region)
    query = 'filter @message like "' + job_id + '" | fields @requestId | sort @timestamp desc | limit 20'
    log_group = '/aws/lambda/invoicing-service-' + stage + '-createInvoice'

    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=int((datetime.today() - timedelta(hours=336)).timestamp()),
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )

    query_id = start_query_response['queryId']

    response = None

    while response == None or response['status'] == 'Running':
        print('Waiting for query to complete ...')
        time.sleep(1)
        response = client.get_query_results(
            queryId=query_id
        )

    try:
        return response['results'][0][0]['value']
    except:
        return "Nothing found."


def find_signoff_invoice_log_request_id(stage, job_id, env_region):
    """
        Uses insights to find request id in create invoice logs
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('logs', region_name=env_region)
    query = 'filter @message like "' + job_id + '" | fields @requestId | sort @timestamp desc | limit 20'
    log_group = '/aws/lambda/invoicing-service-' + stage + '-signOffInvoice'

    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=int((datetime.today() - timedelta(hours=336)).timestamp()),
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )

    query_id = start_query_response['queryId']

    response = None

    while response == None or response['status'] == 'Running':
        print('Waiting for query to complete ...')
        time.sleep(1)
        response = client.get_query_results(
            queryId=query_id
        )
    try:
        return response['results'][0][0]['value']
    except:
        return "Nothing found."


def find_create_invoice_logs(stage, request_id, env_region):
    """
        Uses insights to find logs for create invoice endpoint
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('logs', region_name=env_region)
    query = 'fields @message | filter @requestId = "' + request_id + '" | limit 20 | sort @timestamp desc'
    log_group = '/aws/lambda/invoicing-service-' + stage + '-createInvoice'

    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=int((datetime.today() - timedelta(hours=336)).timestamp()),
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )

    query_id = start_query_response['queryId']

    response = None

    while response == None or response['status'] == 'Running':
        print('Waiting for query to complete ...')
        time.sleep(1)
        response = client.get_query_results(
            queryId=query_id
        )

    return response['results']


def find_signoff_invoice_logs(stage, request_id, env_region):
    """
        Uses insights to find logs for signOff invoice endpoint
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('logs', region_name=env_region)
    query = 'fields @message | filter @requestId = "' + request_id + '" | limit 20 | sort @timestamp desc'
    log_group = '/aws/lambda/invoicing-service-' + stage + '-signOffInvoice'

    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=int((datetime.today() - timedelta(hours=336)).timestamp()),
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )

    query_id = start_query_response['queryId']

    response = None

    while response == None or response['status'] == 'Running':
        print('Waiting for query to complete ...')
        time.sleep(1)
        response = client.get_query_results(
            queryId=query_id
        )

    return response['results']


def find_get_user_logs(job_id, stage, env_region):
    """
        Uses insights to find logs for syncJobs
        1. log type 'syncJob'
        2. log type 'getUser'
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('logs', region_name=env_region)
    query = 'fields @timestamp, `event.headers.User-Agent` | filter @message like "' + job_id + '" AND logId like "getUser" | sort @timestamp desc'
    log_group = '/aws/lambda/jobs-service-' + stage + '-syncJob'

    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=int((datetime.today() - timedelta(hours=336)).timestamp()),
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )

    query_id = start_query_response['queryId']

    response = None

    while response == None or response['status'] == 'Running':
        print('Waiting for query to complete ...')
        time.sleep(1)
        response = client.get_query_results(
            queryId=query_id
        )

    return response['results']


def find_sync_job_logs(job_id, stage, env_region):
    """
        Uses insights to find logs for syncJobs
        1. log type 'syncJob'
        2. log type 'getUser'
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('logs', region_name=env_region)
    query = 'fields @timestamp, oldJobData, newJobData | filter @message like "' + job_id + '" AND logId like "syncJob" | sort @timestamp desc'
    log_group = '/aws/lambda/jobs-service-' + stage + '-syncJob'

    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=int((datetime.today() - timedelta(hours=336)).timestamp()),
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )

    query_id = start_query_response['queryId']

    response = None

    while response == None or response['status'] == 'Running':
        print('Waiting for query to complete ...')
        time.sleep(1)
        response = client.get_query_results(
            queryId=query_id
        )

    return response['results']


def find_cancelled_job_logs(job_id, stage, env_region):
    """
        Uses insights to find logs for syncJobs
        1. log type 'syncJob'
        2. log type 'getUser'
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('logs', region_name=env_region)
    query = 'fields @timestamp, @message | filter @message like "' + job_id + '" AND @message like "Cancellation update DTO" | sort @timestamp desc'
    log_group = '/aws/lambda/jobs-service-' + stage + '-cancelJob'

    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=int((datetime.today() - timedelta(hours=336)).timestamp()),
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )

    query_id = start_query_response['queryId']

    response = None

    while response == None or response['status'] == 'Running':
        print('Waiting for query to complete ...')
        time.sleep(1)
        response = client.get_query_results(
            queryId=query_id
        )

    return response['results']


def find_delete_job_logs(job_id, stage, env_region):
    """
        Uses insights to find logs for deleted jobs
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('logs', region_name=env_region)
    query = 'fields @timestamp | filter @message like "' + job_id + '" | sort @timestamp desc'
    log_group = '/aws/lambda/jobs-service-' + stage + '-deleteJob'

    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=int((datetime.today() - timedelta(hours=336)).timestamp()),
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )

    query_id = start_query_response['queryId']

    response = None

    while response == None or response['status'] == 'Running':
        print('Waiting for query to complete ...')
        time.sleep(1)
        response = client.get_query_results(
            queryId=query_id
        )

    return response['results']


def find_update_job_form_logs(job_id, stage, env_region):
    """
        Uses insights to find logs for updateJobForm
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('logs', region_name=env_region)
    query = 'fields @timestamp, @message | filter @message like "' + job_id + '" | sort @timestamp desc'
    log_group = '/aws/lambda/jobs-service-' + stage + '-updateJobForm'

    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=int((datetime.today() - timedelta(hours=336)).timestamp()),
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )

    query_id = start_query_response['queryId']

    response = None

    while response == None or response['status'] == 'Running':
        print('Waiting for query to complete ...')
        time.sleep(1)
        response = client.get_query_results(
            queryId=query_id
        )

    return response['results']


def find_dispatch_pn_logs(stage, env_region):
    """
        Uses insights to find dispatch push notifications
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('logs', region_name=env_region)
    query = 'fields @timestamp, userId | filter @message like "userId" | sort @timestamp desc'
    log_group = '/aws/lambda/jobs-service-' + stage + '-dispatchNotifications'

    start_query_response = client.start_query(
        logGroupName=log_group,
        startTime=int((datetime.today() - timedelta(hours=24)).timestamp()),
        endTime=int(datetime.now().timestamp()),
        queryString=query,
    )

    query_id = start_query_response['queryId']

    response = None

    while response == None or response['status'] == 'Running':
        print('Waiting for query to complete ...')
        time.sleep(1)
        response = client.get_query_results(
            queryId=query_id
        )

    return response['results']


# SES
def send_password_email(email, password, ses_sender, ses_identity):
    """
        Sends temp password email to user (this does not use mailchimp!)
        Emails are always sent via Ireland, don't change region.
    """
    ses_client = boto3.client('ses', region_name='eu-west-1')
    message = 'Your username is ' + str(email) + ' and temporary password is ' + str(password)
    try:
        response = ses_client.send_email(
            Source=ses_sender,
            Destination={
                'ToAddresses': [
                    email,
                ]
            },
            Message={
                'Subject': {
                    'Data': 'Your temporary password',
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {
                        'Data': str(message),
                        'Charset': 'UTF-8'
                    },
                    'Html': {
                        'Data': str(message),
                        'Charset': 'UTF-8'
                    }
                }
            },
            SourceArn=ses_identity,
            ConfigurationSetName='support_tool_reset_password'
        )
        logger.info('[%s] Email sent with id %s', response['ResponseMetadata']['HTTPStatusCode'], response['MessageId'])
    except Exception as e:
        logger.critical('Email failed with %s', str(e))
        raise Exception(str(e))


# SSM
def get_secret(secret, env_region):
    """
        Gets secret from AWS SSM parameter store
    """
    ssm_client = boto3.client('ssm', region_name=env_region)
    try:
        response = ssm_client.get_parameter(
            Name=secret,
            WithDecryption=True
        )
        return response['Parameter']['Value']
    except Exception as e:
        logger.critical('SSM call failed: %s', str(e))
        raise Exception(str(e))


def get_secret_age(secret, env_region):
    """
        Gets age of secret from AWS SSM parameter store
    """
    ssm_client = boto3.client('ssm', region_name=env_region)
    try:
        response = ssm_client.get_parameter_history(
            Name=secret,
            WithDecryption=True
        )
        return response['Parameters'][0]['LastModifiedDate']
    except Exception as e:
        raise Exception(str(e))


def update_secret(secret, secret_value, env_region):
    """
        Updates secret stored in AWS SSM parameter store
    """
    ssm_client = boto3.client('ssm', region_name=env_region)
    try:
        response = ssm_client.put_parameter(
            Name=secret,
            Value=secret_value,
            Type='SecureString',
            Overwrite=True,
        )
        return response['Version']
    except Exception as e:
        raise Exception(str(e))


# S3
def copy_file_from_s3(bucket, key, download_path):
    """
        Copies file from S3 to local storage
    """
    s3_client = boto3.client('s3')
    s3_client.download_file(bucket, key, download_path)


# Cognito
def set_temp_password(verify_email, password, email, user_pool_id, env_region):

    client = boto3.client('cognito-idp', region_name=env_region)
    try:
        response = client.admin_set_user_password(
            UserPoolId=user_pool_id,
            Username=email,
            Password=password,
            Permanent=False
        )
        logger.info('%s given a temporary password (%s).', email, password)
        return 1, ""
    except Exception as e:
        logger.critical('Error occured: %s', e)
        return 0, e

    if verify_email:
        client = boto3.client('cognito-idp', region_name=env_region)
        try:
            response = client.admin_update_user_attributes(
                UserPoolId=user_pool_id,
                Username=email,
                UserAttributes=[
                    {
                        "Name": "email_verified",
                        "Value": "true"
                    }
                ]
            )
            logger.info('Also %s set to verified.', email)
        except Exception as e:
            logger.critical('Error occured: %s', e)


def manage_admin_user(manage_job, email, admin_user_pool_id, env_region):
    """
        creates or updates (if required) an admin user
    """
    client = boto3.client('cognito-idp', region_name=env_region)
    try:
        response = client.admin_create_user(
            UserPoolId=admin_user_pool_id,
            Username=email,
            UserAttributes=[
                {
                    "Name": "email",
                    "Value": email
                },
                {
                    "Name": "email_verified",
                    "Value": "true"
                }
            ]
        )
        logger.info('Admin user %s created.', email)
    except ClientError as e:
        if e.response['Error']['Code'] == 'UsernameExistsException':
            logger.info('Admin user %s already created, no action taken.', email)
        else:
            raise Exception(str(e))

    # check to see if we need to add user to perm_manage_job group
    if manage_job:
        try:
            response = client.admin_add_user_to_group(
                UserPoolId=admin_user_pool_id,
                Username=email,
                GroupName='PERM_MANAGE_JOBS'
            )
            logger.info('Admin user %s added to permission group.', email)
        except Exception as e:
            raise Exception(str(e))


#DynamoDB
def get_engineer_details(device, stage, env_region):
    """
        Get the engineer device and last log on details
        Parameter: none
    """
    engineer_list = []
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('dynamodb', region_name=env_region)
    paginator = client.get_paginator('scan')
    operation_parameters = {
        'TableName': 'contractorUsers-' + stage,
        'FilterExpression': 'contains(mobileUserAgent, :e)',
        'ExpressionAttributeValues': {
            ':e': {'S': device}
        }
    }

    try:
        page_iterator = paginator.paginate(**operation_parameters)
        for page in page_iterator:
            for item in page["Items"]:
                try:
                    mobileAgent = item['mobileUserAgent']['S']
                except:
                    mobileAgent = "Empty"
                try:
                    last_login = item['updatedAt']['S']
                except:
                    last_login = "Empty"
                try:
                    email = item['email']['S']
                except:
                    email = "Empty"
                logger.info(f'Database scan found {email}, {mobileAgent} and {last_login}')
                engineer = {
                    'email': email,
                    'last_login': last_login,
                    'mobile_agent': mobileAgent
                }
                engineer_list.append(engineer)

        return engineer_list
    except Exception as e:
        logger.info(f'[{device}]: {e}')
        raise Exception(str(e))


def get_auth_id(email_address, stage, env_region):
    """
        Get the engineer's authID, contractor ID,
        mobile version and PN tokens
        Parameter: email_address (required)
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('dynamodb', region_name=env_region)
    paginator = client.get_paginator('scan')
    operation_parameters = {
        'TableName': 'contractorUsers-' + stage,
        'FilterExpression': 'email = :e',
        'ExpressionAttributeValues': {
            ':e': {'S': email_address}
        }
    }
    logger.info(f'Using {stage}, {env_region} & {operation_parameters}')

    try:
        page_iterator = paginator.paginate(**operation_parameters)
        for page in page_iterator:
            try:
                auth_id = page['Items'][0]['authID']['S']
            except:
                auth_id = ""
            try:
                contractor = page['Items'][0]['contractor']['N']
            except:
                contractor = ""
            try:
                version_number = page['Items'][0]['mobileUserAgent']['S']
            except:
                version_number = ""
            try:
                pn_tokens = []
                for pn_token in page['Items'][0]['pnTokens']['L']:
                    pn_tokens.append(pn_token['S'])
            except:
                pn_tokens = []
            # for some reason this started to return an extra empty page which was bombing out
            if auth_id:
                break

        logger.info(f'Database scan found the following: {auth_id}, {contractor} and {version_number}')
        return auth_id, contractor, version_number, pn_tokens
    except Exception as e:
        logger.info(f'[{email_address}]: {e}')
        raise Exception(str(e))


def get_contractor_email(auth_id, stage, env_region):
    """
        Get the engineer's email
        Parameter: auth_id (required)
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('dynamodb', region_name=env_region)
    paginator = client.get_paginator('scan')
    operation_parameters = {
        'TableName': 'contractorUsers-' + stage,
        'FilterExpression': 'contains(authID, :e)',
        'ExpressionAttributeValues': {
            ':e': {'S': auth_id}
        }
    }

    try:
        page_iterator = paginator.paginate(**operation_parameters)
        for page in page_iterator:
            email = page['Items'][0]['email']['S']
            contractor = page['Items'][0]['contractor']['N']
            # for some reason this started to return an extra empty page which was bombing out
            if email:
                break

        logger.info(f'Database scan for {auth_id} found {email} & {contractor}')
        return email, contractor
    except Exception as e:
        logger.info(f'Searching for authID {auth_id} resulted in {e}')
        raise Exception(str(e))


def get_job_details(job_id, stage, env_region):
    """
        Get the a single job's status
        Parameter: email_address (required)
    """
    if stage == 'uat':
        stage = 'test'
    client = boto3.client('dynamodb', region_name=env_region)
    paginator = client.get_paginator('scan')
    operation_parameters = {
        'TableName': 'jobs-' + stage,
        'FilterExpression': 'id = :id',
        'ExpressionAttributeValues': {
            ':id': {'N': job_id}
        }
    }

    try:
        page_iterator = paginator.paginate(**operation_parameters)
        for page in page_iterator:
            for item in page["Items"]:
                keep_going = False
                job_milestones = item['milestones']['M']
                for k, v in job_milestones.items():
                    if k in ("jobCompleted", "jobAborted"):
                        keep_going = True
                if keep_going:
                    status = item['status']['S']
                    assigned_user = item['assignedUserID']['S']
                    contractor = item['contractor']['N']

                    logger.info(f'Database scan found the following: {status}, {assigned_user} and {contractor}')
                    return [{"Job status": status}, {"Assigned User": assigned_user}, {"Contractor ID": contractor}]
                else:
                    logger.info(f'{job_id}: Job not in a payable status.')
                    return
        logger.info(f'{job_id}: Database scan did not find the job.')
    except Exception as e:
        logger.info(f'[{job_id}]: {e}')
        raise Exception(str(e))


def get_job_list(auth_id, stage, env_region):
    """
        Gets the engineer's open jobs
        Parameter: auth_id (required)
    """
    if stage == 'uat':
        stage = 'test'
    job_list = []
    client = boto3.client('dynamodb', region_name=env_region)
    paginator = client.get_paginator('scan')
    operation_parameters = {
        'TableName': 'jobs-' + stage,
        'FilterExpression': 'contains(assignedUserID, :a) AND contains(#job_status, :s)',
        'ExpressionAttributeValues': {
            ':a': {'S': auth_id},
            ':s': {'S': 'not-closed'}
        },
        'ExpressionAttributeNames': {
            "#job_status": "status"
        }
    }

    try:
        page_iterator = paginator.paginate(**operation_parameters)
        for page in page_iterator:
            for item in page['Items']:
                keep_going = True
                job_milestones = item['milestones']['M']
                for k, v in job_milestones.items():
                    if k in ("jobCompleted", "jobCancelled", "jobAborted"):
                        keep_going = False
                if keep_going:
                    job_id = item['id']['N']
                    try:
                        job_trade = item['trade']['S']
                    except:
                        job_trade = item['trade']['L'][0]['S']
                    try:
                        job_type = item['type']['S']
                    except:
                        job_type = "NONE"
                    job_requested_appointment = item['requestedAppointment']['M']
                    job_postcode = item['propertyLocation']['M']['postCode']['S']
                    job_milestones = parse_job_milestones(job_milestones)
                    try:
                        job_actions = parse_job_actions(item['appointments']['L'])
                    except:
                        job_actions = ""
                    job = {
                        'id': job_id,
                        'trade': job_trade,
                        'type': job_type,
                        'postcode': job_postcode,
                        'milestones': job_milestones,
                        'actions': job_actions,
                        'reqestedAppointment': job_requested_appointment,
                        'requestSlot': work_out_slot(job_requested_appointment)
                    }
                    job_list.append(job)

        logger.info(f'Current job list: {job_list}')
        return job_list
    except Exception as e:
        logger.info(f'[{job_id}]: {e}')
        raise Exception(str(e))


def get_yesterdays_job_list(stage, env_region):
    """
        Geta list of jobs from yesterday
        N/A Parameter: post_code (required)
    """
    if stage == 'uat':
        stage = 'test'
    job_id = "No jobs parsed yet!"
    job_list = []
    area_list = []
    # yesterday_date = str(date.today() - timedelta(days = 1))
    yesterday_date = str(date.today())
    client = boto3.client('dynamodb', region_name=env_region)
    paginator = client.get_paginator('scan')
    operation_parameters = {
        'TableName': 'jobs-' + stage,
        'FilterExpression': 'contains(requestedAppointment.#request_date, :d)',
        'ExpressionAttributeValues': {
            ':d': {'S': yesterday_date}
        },
        'ExpressionAttributeNames': {
            "#request_date": "date"
        }
    }

    try:
        page_iterator = paginator.paginate(**operation_parameters)
        for page in page_iterator:
            for item in page['Items']:
                job_milestones = item['milestones']['M']
                job_id = item['id']['N']
                try:
                    job_trade = item['trade']['S']
                except:
                    job_trade = item['trade']['L'][0]['S']
                job_requested_appointment = item['requestedAppointment']['M']
                job_milestones = parse_job_milestones(job_milestones)
                property_area = item['propertyLocation']['M']['areaLabel']['S']
                try:
                    job_actions = parse_job_actions(item['appointments']['L'])
                except:
                    job_actions = ""
                try:
                    assigned_user = get_contractor_email(
                                        item['assignedUserID']['S'],
                                        stage,
                                        env_region
                                    )
                except:
                    assigned_user = ""
                job = {
                    'id': job_id,
                    'trade': job_trade,
                    'milestones': job_milestones,
                    'actions': job_actions,
                    'reqestedAppointment': job_requested_appointment,
                    'areaLabel': property_area,
                    'assignedUser': assigned_user
                }
                job_list.append(job)

        return job_list
    except Exception as e:
        logger.info(f'[{job_id}]: {e}')
        raise Exception(str(e))


def get_completed_job_list(auth_id, stage, env_region):
    """
        Gets the engineer's Finished jobs
        Parameter: auth_id (required)
    """
    if stage == 'uat':
        stage = 'test'
    job_list = []

    client = boto3.client('dynamodb', region_name=env_region)
    paginator = client.get_paginator('scan')
    operation_parameters = {
        'TableName': 'jobs-' + stage,
        'FilterExpression': 'contains(assignedUserID, :a)',
        'ExpressionAttributeValues': {
            ':a': {'S': auth_id}
        }
    }

    try:
        page_iterator = paginator.paginate(**operation_parameters)
        for page in page_iterator:
            for item in page['Items']:
                keep_going = False
                job_milestones = item['milestones']['M']
                for k, v in job_milestones.items():
                    if k in ("jobCompleted", "jobCancelled", "jobAborted"):
                        keep_going = True
                if keep_going:
                    job_id = item['id']['N']
                    try:
                        job_trade = item['trade']['S']
                    except:
                        try:
                            job_trade = item['trade']['L'][0]['S']
                        except:
                            job_trade = item['claims']['L'][0]['M']['claimType']['S']
                    job_requested_appointment = item['requestedAppointment']['M']
                    job_milestones = parse_job_milestones(job_milestones)
                    try:
                        job_actions = parse_job_actions(item['appointments']['L'])
                    except:
                        job_actions = ""
                    status = item['status']['S']
                    invoice_status = get_invoice_row(job_id, stage, env_region)
                    job = {
                        'id': job_id,
                        'trade': job_trade,
                        'milestones': job_milestones,
                        'actions': job_actions,
                        'reqestedAppointment': job_requested_appointment,
                        'status': status,
                        'invoice_status': invoice_status
                    }
                    job_list.append(job)

        return job_list
    except Exception as e:
        logger.info(f'[{job_id}]: {e}')
        raise Exception(str(e))


def get_invoice_row(job_id, stage, env_region):
    """
        Gets the row on the invoices table for corresponding job ID
    """
    if stage == 'uat':
        stage = 'test'

    client = boto3.client('dynamodb', region_name=env_region)
    paginator = client.get_paginator('scan')
    operation_parameters = {
        'TableName': 'invoice-' + stage,
        'FilterExpression': 'contains(jobID, :a)',
        'ExpressionAttributeValues': {
            ':a': {'S': job_id}
        }
    }

    try:
        page_iterator = paginator.paginate(**operation_parameters)
        for page in page_iterator:
            for item in page['Items']:
                logger.info(f'Succeeded: {item}')
                return item
    except Exception as e:
        logger.info(f'Error: {e}')
        raise Exception(str(e.response['Error']['Message']))


#misc utilities
def create_temp_password():
    """
        copied from stackoverflow and tweaked to comply
        with AWS cognito password rules
    """
    char_classes = (string.ascii_lowercase,
                    string.ascii_uppercase,
                    string.digits,
                    string.punctuation)

    char = lambda: secrets.choice(secrets.choice(char_classes))

    while True:
        password = ''.join([char() for _ in range(8)])
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and any(c.isdigit() for c in password)
                and any((c in string.punctuation) for c in password)):
            break

    return password


def parse_job_milestones(milestones):
    """
        Collates milestones into something easily manageable in jinja
        Parameters: milestones (required)
    """
    job_milestones = []
    for k, v in milestones.items():
        if k == 'jobRaised':
            job_milestones.append({'jobRaised': v['M']['timestamp']['S']})
        if k == 'jobDispatched':
            job_milestones.append({'jobDispatched': v['M']['timestamp']['S']})
        if k == 'jobAccepted':
            job_milestones.append({'jobAccepted': v['M']['timestamp']['S']})
        if k == 'jobCompleted':
            job_milestones.append({'jobCompleted': v['M']['timestamp']['S']})
        if k == 'jobAborted':
            job_milestones.append({'jobAborted': v['M']['timestamp']['S']})
        if k == 'jobCancelled':
            job_milestones.append({'jobCancelled': v['M']['timestamp']['S']})

    return job_milestones


def parse_job_actions(actions):
    """
        Collates actions taken by engineer in the app into something
        easily manageable in jinja
        Parameters: actions (required)
    """
    if actions is None:
        return ""

    i = 1
    user_actions = []
    appointment_actions = []
    for action in actions:
        for k, v in action['M'].items():
            if k == 'date':
                appointment_actions.append({'date': v['S']})
            if k == 'start':
                appointment_actions.append({'start': v['S']})
            if k == 'stop':
                appointment_actions.append({'stop': v['S']})
            if k == 'onRoute':
                appointment_actions.append(
                    {
                        'onRoute':
                            {
                                'notified': v['M']['notified']['BOOL'],
                                'timestamp': v['M']['timestamp']['S']
                            }
                    }
                )

        appointment = {
            str(i): appointment_actions
        }
        user_actions.append(appointment)
        i += 1
        appointment_actions = []

    return user_actions


def work_out_slot(data):
        if data['appointmentSlot']['S'] == "0800 - 1300":
            return "Morning"
        if data['appointmentSlot']['S'] == "1200 - 1800":
            return "Afternoon"
        if data['appointmentSlot']['S'] == "1700 - 2200":
            return "Evening"
        if data['appointmentSlot']['S'] == "0800 - 1800":
            return "All Day"

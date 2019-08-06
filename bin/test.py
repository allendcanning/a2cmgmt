#!/usr/local/bin/python3 

import os
from optparse import OptionParser
import boto3
import botocore
from botocore.exceptions import ClientError
import hmac
import base64
import hashlib
import json

def Usage():
  parser.print_help()

def log_error(msg):
    print(msg)

def get_config_data(session):
  client = session.client('ssm')
  environments = [ 'dev', 'prod' ]
  config = {}

  for environment in environments:
    config[environment] = {}
    ssmpath="/a2c/"+environment+"/s3_html_bucket"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['s3_html_bucket'] = response['Parameter']['Value']
  
    ssmpath="/a2c/"+environment+"/cognito_pool"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['cognito_pool'] =response['Parameter']['Value'] 

    ssmpath="/a2c/"+environment+"/mgmt_cognito_client_id"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['cognito_client_id'] =response['Parameter']['Value'] 

    ssmpath="/a2c/"+environment+"/mgmt_cognito_client_secret_hash"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['cognito_client_secret_hash'] =response['Parameter']['Value'] 

    ssmpath="/a2c/"+environment+"/table_name"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['table_name'] =response['Parameter']['Value'] 

    ssmpath="/a2c/"+environment+"/admin_cognito_pool"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['admin_cognito_pool'] =response['Parameter']['Value'] 

    ssmpath="/a2c/"+environment+"/admin_cognito_client_id"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['admin_cognito_client_id'] =response['Parameter']['Value'] 

    ssmpath="/a2c/"+environment+"/admin_cognito_client_secret_hash"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['admin_cognito_client_secret_hash'] =response['Parameter']['Value'] 

    ssmpath="/a2c/"+environment+"/admin_cognito_auth_url"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['cognito_auth_url'] =response['Parameter']['Value'] 

    ssmpath="/a2c/"+environment+"/admin_content_url"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['admin_content_url'] =response['Parameter']['Value'] 

    ssmpath="/a2c/"+environment+"/coaches_table_name"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['coaches_table_name'] =response['Parameter']['Value'] 
  
    ssmpath="/a2c/"+environment+"/ses_configuration_set"
    response = client.get_parameter(Name=ssmpath,WithDecryption=False)
    config[environment]['ses_configuration_set'] =response['Parameter']['Value'] 

#  for env in config:
#    for item in config[env]:
#      log_error("For Env ["+env+"] Got config key = "+item+" value = "+config[env][item])

  return config

def authenticate_user(session,config,environment,authparams):
  # Get cognito handle
  cognito = session.client('cognito-idp')

  message = authparams['USERNAME'] + config[environment]['admin_cognito_client_id']
  dig = hmac.new(key=bytes(config[environment]['admin_cognito_client_secret_hash'],'UTF-8'),msg=message.encode('UTF-8'),digestmod=hashlib.sha256).digest()

  authparams['SECRET_HASH'] = base64.b64encode(dig).decode()

  #log_error('Auth record = '+json.dumps(authparams))

  # Initiate Authentication
  try:
    response = cognito.admin_initiate_auth(UserPoolId=config[environment]['admin_cognito_pool'],
                                 ClientId=config[environment]['admin_cognito_client_id'],
                                 AuthFlow='ADMIN_NO_SRP_AUTH',
                                 AuthParameters=authparams)
    #log_error(json.dumps(response))
  except ClientError as e:
    log_error('Admin Initiate Auth failed: '+e.response['Error']['Message'])
    return 'False'

  return response['AuthenticationResult']['IdToken']

# Set "running_locally" flag if you are running the integration test locally
running_locally = True
function_name = "mgmtPortalFunction"
authparams = {}
eventlocation = os.getcwd()+"/events"
authparams['USERNAME'] = "canning"
authparams['PASSWORD'] = "Hunter98!"

# Begin of main section
parser = OptionParser()
parser.add_option("-a", "--aws", dest="aws",help="AWS Profile")
parser.add_option("-e", "--environment", dest="environment",help="Application Environment - defaults to dev")
parser.add_option("-r", "--region", dest="region",help="AWS Region - defaults to us-east-1")

(options, args) = parser.parse_args()

if options.region:
  region = options.region
else:
  region = "us-east-1"

if options.aws:
  session = boto3.Session(profile_name=options.aws,region_name=region)
else:
  session = boto3.Session(region_name=region)

if options.environment:
  environment = options.environment
else:
  environment = "dev"

config = get_config_data(session)
token = authenticate_user(session,config,environment,authparams)

# Build the base event json
base_event = { 
  "requestContext": {
        "elb": {
            "targetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:530317771161:targetgroup/a2c-s-Targe-1GJ96K1I6ISOG/b002feeae0c81b88"
        }
    },
    "httpMethod": "GET",
    "path": "/",
    "queryStringParameters": "",
    "headers": {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
        "host": "adminportal.thefirmu.org",
        "x-amzn-oidc-accesstoken": token,
    },
    "body": "",
    "isBase64Encoded": "true"
}

if running_locally:
    # Create Lambda SDK client to connect to appropriate Lambda endpoint
    lambda_client = session.client('lambda',
        region_name=region,
        endpoint_url="http://127.0.0.1:3001",
        use_ssl=False,
        verify=False,
        config=botocore.client.Config(
            signature_version=botocore.UNSIGNED,
            read_timeout=10,
            retries={'max_attempts': 0},
        )
    )
else:
    lambda_client = session.client('lambda')

# Invoke your Lambda function as you normally usually do. The function will run
# locally if it is configured to do so
response = lambda_client.invoke(
    FunctionName=function_name,
    Payload=bytes(json.dumps(base_event),'UTF-8')
)

# Verify the response
print("Syntax...")
if 'StatusCode' in response:
  if response['StatusCode'] >= 200 and response['StatusCode'] < 300:
    print("ok")
  else:
    log_error(response['StatusCode'])
    if 'FunctionError' in response:
      log_error(response['FunctionError'])

# check GET responses
for file in os.listdir(eventlocation):
    if file.startswith("get"):
      with open(eventlocation+"/"+file) as event_file:
        print("Testing event "+file)
        event = json.load(event_file)
        event['headers']['x-amzn-oidc-accesstoken'] = token
        response = lambda_client.invoke(
          FunctionName=function_name,
          Payload=bytes(json.dumps(event),'UTF-8')
        )
        if 'StatusCode' in response:
           if response['StatusCode'] >= 200 and response['StatusCode'] < 300:
             print("ok")
           else:
             log_error(response['StatusCode'])
             if 'FunctionError' in response:
               log_error(response['FunctionError']) 

# check POST responses

import json
import os, time
import re
import boto3
import hmac
import hashlib
import base64
from jose import jwk, jwt
from jose.utils import base64url_decode
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import urllib.parse
from urllib.request import urlopen

# Set timezone
os.environ['TZ'] = 'US/Eastern'
time.tzset()

# Open DB connection
dynamodb = boto3.resource('dynamodb')

# This information needs to move to paramater store
table_name = "user_info"

# Connect to dynamo db table
t = dynamodb.Table(table_name)

def log_error(msg):
  print(msg)

def get_config_data(environment):
  client = boto3.client('ssm')
  config = {}

  ssmpath="/a2c/"+environment+"/s3_html_bucket"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['s3_html_bucket'] = response['Parameter']['Value']
  
  ssmpath="/a2c/"+environment+"/cognito_pool"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['cognito_pool'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/cognito_client_id"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['cognito_client_id'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/cognito_client_secret_hash"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['cognito_client_secret_hash'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/content_url"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['content_url'] =response['Parameter']['Value'] 

  for item in config:
    log_error("Got config key = "+item+" value = "+config[item])

  return config

def start_html(config):
  # Build HTML content
  css = '<link rel="stylesheet" href="https://s3.amazonaws.com/'+config['s3_html_bucket']+'/css/a2c.css" type="text/css" />'
  content = "<html><head><title>A2C Portal</title>\n"
  content += css+'</head>'
  content += "<body><h3>A2C Portal</h3>"

  return content

def print_form():
  content = '<form method="post" action="">'
  content += 'Enter Username: <input type="text" name="username"><p>\n'
  content += 'Enter Phone: <input type="text" name="phone"><p>\n'
  content += '<input type="submit" name="Submit">'
  content += '</form>'

  return content

def add_cognito_user(config,record):
  cognito = boto3.client('cognito-idp')
  retval = {}

  # Create cognito pool user
  try:
    response = cognito.admin_create_user(
      UserPoolId=config['cognito_pool'],
      Username=record['username'],
      UserAttributes=[
        {
            'Name': 'email',
            'Value': record['email'] 
        },
        {
            'Name': 'phone',
            'Value': record['phone']
        }
      ]
    )
    retval['state'] = True
    retval['message'] = "Successfully added user"
  except ClientError as e:
    log_error("response = "+json.dumps(e.response))
    log_error("Error is "+e.response['Error']['Message'])
    retval['status'] = False
    retval['message'] = e.response['Error']['Message']

  return retval

def add_dynamo_user(record):
  retval = {}

  # Add some error handling
  try:
    for item in record:
      if record[item] == "":
        record[item] = None
    t.put_item(Item=record)
    retval['status'] = True
    retval['message'] = "Successfully added user"
  except ClientError as e:
    log_error("response = "+json.dumps(e.response))
    log_error("Error is "+e.response['Error']['Message'])
    retval['status'] = False
    retval['message'] = e.response['Error']['Message']
  
  return retval

def mgmt_handler(event, context):
  token = False
  environment = "dev"

  log_error("Event = "+json.dumps(event))

  config = get_config_data(environment)
  
  content = start_html(config)

  # Parse form params

  if action == "Add":
      response = add_cognito_user(user_record)
      if not response['status']:
          content += "<h3>Unable to add user to cognito pool - "+response['message']+"</h3>"
      response = add_dynamo_user(user_record)
      if not response['status']:
          content += "<h3>Unable to add user to dynamo db - "+response['message']+"</h3>"
  else:
    content += print_form()

  content += "</body></html>"

  cookie = 'Token='+str(token)
  return {
    'statusCode': 200,
    'headers': {
      'Content-type': 'text/html',
      'Set-Cookie': cookie
    },
    'body': content
  }
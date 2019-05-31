import json
import os, time
import re
import boto3
#import hmac
#import hashlib
import base64
#from jose import jwk, jwt
#from jose.utils import base64url_decode
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

  ssmpath="/a2c/"+environment+"/mgmt_cognito_client_id"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['cognito_client_id'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/mgmt_cognito_client_secret_hash"
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
  content += 'Enter Mobile Phone: <input type="tel" id="phone" name="phone" pattern="[0-9]{3}[0-9]{3}[0-9]{4}"><p>\n'
  content += 'Enter Email Address: <input type="email" name="email"><p>\n'
  content += '<input type="hidden" name="action" value="add">\n'
  content += '<input type="submit" name="Submit">'
  content += '</form>'

  return content

def add_cognito_user(config,record):
  cognito = boto3.client('cognito-idp')
  retval = {}

  log_error('Inside add cognito')
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
            'Value': '+1'+record['phone']
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

  log_error('retval = '+str(retval))
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
  action = "False"
  environment = "dev"
  user_record = {}

  log_error("Event = "+json.dumps(event))

  config = get_config_data(environment)
  
  content = start_html(config)

  # Parse form params
  if 'body' in event:
    if bool(event['body'] and event['body'].strip()):
      # Parse the post parameters
      postparams = event['body']
      postparams = base64.b64decode(bytes(postparams,'UTF-8')).decode('utf-8')
      log_error('Got post params = '+postparams)
      raw_record = urllib.parse.parse_qs(postparams)
      for item in raw_record:
        user_record[item] = raw_record[item][0]

    log_error('user_record = '+str(user_record))
    if 'action' in user_record:
      if user_record['action'] == 'add':
        response = add_cognito_user(config,user_record)
        if not response['status']:
          content += "<h3>Unable to add user to cognito pool - "+response['message']+"</h3>"
        else:
          content += '<h3>Successfully added user to cognito pool</h3>\n'
        response = add_dynamo_user(user_record)
        if not response['status']:
          content += "<h3>Unable to add user to dynamo db - "+response['message']+"</h3>"
        else:
          content += '<h3>Successfully added user to dynamo db</h3>\n'
    else:
      content += print_form()
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
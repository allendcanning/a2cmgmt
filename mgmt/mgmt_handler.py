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

  ssmpath="/a2c/"+environment+"/table_name"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['table_name'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/admin_content_url"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['content_url'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/admin_cognito_pool"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['admin_cognito_pool'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/admin_cognito_client_id"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['admin_cognito_client_id'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/admin_cognito_client_secret_hash"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['admin_cognito_client_secret_hash'] =response['Parameter']['Value'] 

  ssmpath="/a2c/"+environment+"/admin_cognito_auth_url"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['cognito_auth_url'] =response['Parameter']['Value'] 

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

def print_top_menu():
  content = '<h3>The Firm U Administration Portal</h3>\n'
  content += '<a href="?action=add_user">Add User to The FirmU</a>'
  content += '<a href="?action=rm_user">Remove User from The FirmU</a>'
  content += '<a href="?action=email_coaches">Email Coaches</a>'

  return content 
  
def print_rm_user_form():
  content = '<h3>The Firm U Remove a User page</h3>\n'
  content = '<form method="post" action="">'
  content += 'Enter Username: <input type="text" name="username"><p>\n'
  content += '<input type="hidden" name="action" value="rm">\n'
  content += '<input type="submit" name="Submit">'
  content += '</form>'

def print_add_user_form():
  content = '<form method="post" action="">'
  content += 'Enter Username: <input type="text" name="username"><p>\n'
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
        }
      ]
    )
    retval['status'] = True
    retval['message'] = "Successfully added user"
  except ClientError as e:
    log_error("response = "+json.dumps(e.response))
    log_error("Error is "+e.response['Error']['Message'])
    retval['status'] = False
    retval['message'] = e.response['Error']['Message']

  log_error('retval = '+str(retval))
  return retval

def rm_cognito_user(config,record):
  cognito = boto3.client('cognito-idp')
  retval = {}

  log_error('Inside add cognito')
  # Create cognito pool user
  try:
    response = cognito.admin_delete_user(
      UserPoolId=config['cognito_pool'],
      Username=record['username']
    )
    retval['status'] = True
    retval['message'] = "Successfully removed user"
  except ClientError as e:
    log_error("response = "+json.dumps(e.response))
    log_error("Error is "+e.response['Error']['Message'])
    retval['status'] = False
    retval['message'] = e.response['Error']['Message']

  log_error('retval = '+str(retval))
  return retval

def add_dynamo_user(config,record):
  # Make connection to DB table
  t = dynamodb.Table(config['table_name'])

  retval = {}

  # Delete the action item
  if 'action' in record:
    del record['action']

  if 'Submit' in record:
    del record['Submit']

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

def check_token(config,event):
  token = 'False'
  auth_record = {}
  auth_record['token'] = 'False'
  auth_record['username'] = 'False'

  # Get jwt token
  if 'headers' in event:
    if event['headers'] != None:
      if 'cookie' in event['headers']:
        cookie = event['headers']['cookie']
        if ';' in cookie:
          cookies = cookie.split(';')
          if 'AWSELBAuthSessionCookie-0' in cookies:
            token = cookies['AWSELBAuthSessionCookie-0'].split('=')[1]
            log_error('Got Token = '+token)
            if token != 'False':
              auth_record = validate_token(config,token)
      elif 'x-amzn-oidc-accesstoken' in event['headers']:
        token = event['headers']['x-amzn-oidc-accesstoken']
        log_error('Got Token = '+token) 
        auth_record = validate_token(config,token)

  return auth_record

def getTokenFromOauthCode(config,code,redirect_uri):
  auth_header = base64.b64encode(bytes(config['admin_cognito_client_id']+':'+config['admin_cognito_client_secret_hash'],'UTF-8'))
  data = {
    "grant_type": "authorization_code",
    "code": code,
    "client_id": config['admin_cognito_client_id'],
    "redirect_uri": redirect_uri
  }
  r = requests.post(config['cognito_auth_url']+'token',auth=auth_header,data=data)

  res = r.json()

  return res['id_token']

def mgmt_handler(event, context):
  token = False
  action = "False"
  environment = "dev"
  user_record = {}

  log_error("Event = "+json.dumps(event))

  config = get_config_data(environment)

  # Check for token
  auth_record = check_token(config,event)

  content = start_html(config)

  if auth_record['token'] == 'False':
    if 'queryStringParameters' in event:
      if event['queryStringParameters'] != None:
        if 'code' in event['queryStringParameters']:
          token = getTokenFromOauthCode(code)
          log_error("Token = ",token)
        else:
          # Redirect to oauth login form
          url = config['cognito_auth_url']+"authorize?response_type=code&scope=openid&client_id="+config['admin_cognito_client_id']+"&redirect_uri="+config['content_url']
          log_error("Sending to "+url)

          return { 'statusCode': 301,
           'headers': {
              'Location': url,
              'Cache-Control': 'no-store'
           }
          }
  else:
    token = auth_record['token']

    if 'queryStringParameters' in event:
      if event['queryStringParameters'] != None:
        if 'action' in event['queryStringParameters']:
          if action == 'add_user':
            content += print_add_user_form()
          elif action == 'email_coaches':
            content += '<h3>This has not been implemented as of yet</h3>'
          else:
            content += print_top_menu()
    # Parse form params
    elif 'body' in event:
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
          response = add_dynamo_user(config,user_record)
          if not response['status']:
            content += "<h3>Unable to add user to dynamo db - "+response['message']+"</h3>"
          else:
            content += '<h3>Successfully added user to dynamo db</h3>\n'
        elif user_record['action'] == 'rm':
          response = rm_cognito_user(config,user_record)
          if not response['status']:
            content += "<h3>Unable to remove user from cognito pool - "+response['message']+"</h3>"
          else:
            content += '<h3>Successfully removed user from cognito pool</h3>\n'
        elif user_record['action'] == 'email':
          content += '<h4>This has not been implemented yet</h4>'
      else:
        content += print_top_menu()
    else:
      content += print_top_menu()

    content += "</body></html>"

  return {
    'statusCode': 200,
    'headers': {
      'Content-type': 'text/html',
      'Cache-Control': 'no-store'
    },
    'body': content
  }
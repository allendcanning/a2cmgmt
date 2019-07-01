import json
import os, time
import re
import boto3
#import hmac
#import hashlib
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

  ssmpath="/a2c/"+environment+"/tmpl_table_name"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['tmpl_table_name'] =response['Parameter']['Value'] 
  
  for item in config:
    log_error("Got config key = "+item+" value = "+config[item])

  return config

def start_html(config):
  # Build HTML content
  css = '<link rel="stylesheet" href="https://s3.amazonaws.com/'+config['s3_html_bucket']+'/css/a2c.css" type="text/css" />'
  content = "<html><head><title>A2C Portal</title>\n"
  content += css+'</head>'
  content += "<body>"

  return content

def print_top_menu():
  content = '<h3>The Firm U Administration Portal</h3>\n'
  content += '<a href="?action=add_user">Add User to The FirmU</a><br>'
  content += '<a href="?action=rm_user">Remove User from The FirmU</a><br>'
  content += '<a href="?action=add_tmpl">Add Email Templates</a><br>'
  content += '<a href="?action=email_tmpl">Edit Email Templates</a><br>'
  content += '<a href="?action=email_coaches">Email Coaches</a><br>'

  return content 
  
def print_rm_user_form():
  content = '<h3>The Firm U Remove a User page</h3>\n'
  content += '<form method="post" action="">'
  content += 'Enter Username: <input type="text" name="username"><p>\n'
  content += '<input type="hidden" name="action" value="rm">\n'
  content += '<input type="submit" name="Submit">'
  content += '</form>'
  content += '<p><a href="">Back to Admin page</a>'

def print_add_user_form():
  content = '<h4>Add a user to The FirmU</h4>'
  content += '<form method="post" action="/">'
  content += 'Enter Username: <input type="text" name="username"><p>\n'
  content += 'Enter Email Address: <input type="email" name="email"><p>\n'
  content += '<input type="hidden" name="action" value="add">\n'
  content += '<input type="submit" name="Submit">'
  content += '</form>'
  content += '<p><a href="">Back to Admin page</a>'

  return content

def add_email_template(config,template):
  client = boto3.client('ses')
  try:
    response = client.create_template(Template=template)
    retval['status'] = True
    retval['message'] = 'Successfully updates email template'
  except ClientError as e:
    log_error("response = "+json.dumps(e.response))
    log_error("Error is "+e.response['Error']['Message'])
    retval['status'] = False
    retval['message'] = e.response['Error']['Message']

  return retval

def update_email_template(config,template):
  client = boto3.client('ses')
  try:
    response = client.update_template(Template=template)
    retval['status'] = True
    retval['message'] = 'Successfully updates email template'
  except ClientError as e:
    log_error("response = "+json.dumps(e.response))
    log_error("Error is "+e.response['Error']['Message'])
    retval['status'] = False
    retval['message'] = e.response['Error']['Message']

  return retval

def print_email_templates(config,name):
  client = boto3.client('ses')
  tmpls = client.list_templates()

  log_error("Got name: "+str(name))
  log_error("Got SES templates: "+str(tmpls))

  content = '<h3>The FirmU Email template editing program</h3>'
  content += '<p>Make sure you fill out both the HTML and Text sections, as both will be sent out to the recipients. '
  content += 'You can use variables to be sent in your email by surrounding them with {{}}.  The following variables are available:<br>'
  content += '{{coachname}}<br>{{athletename}}<br>{{sport}}'

  if tmpls['TemplatesMetadata'] and name:
    # Add AJAX to get template info when the template name is changed
    content += '<form method="POST" action="/">\nSelect a template to edit: <select name="TemplateName">'

    default = {}
    # display template list
    for tmpl in tmpls['TemplatesMetadata']:
      content += '<option value='+tmpl['Name']
      if tmpl['Name'] == name:
        template = client.get_template(TemplateName=tmpl['Name'])
        content += ' selected '
        default['TemplateName'] = template['TemplateName']
        default['SubjectPart'] = template['SubjectPart']
        default['HtmlPart'] = template['HtmlPart']
        default['TextPart'] = template['TextPart']
      content += '>'+template['TemplateName']+'</option>\n'
    content += '</select>'

    # load default template into text area for editing>'
    content += '<br>Subject: <input type="text" name="SubjectPart" size="40" value="'+default['SubjectPart']+'"><br>\n'
    content += 'HTML message: <textarea rows="25" cols="50" name="HtmlPart">'
    content += default['HtmlPart']
    content += '</textarea><p>\n'

    content += 'Text message: <textarea rows="25" cols="50" name="TextPart">'
    content += default['TextPart']
    content += '</textarea><p>\n'

    content += '<input type="hidden" name="action" value="update_tmpl"><br>\n'
    content += '<input type="submit" name="Submit">'
    content += '<input type="reset">'
    content += '</form>'
  else:
    content += '<form method="POST" action="/">Enter template name: <input type="text" name="TemplateName">'
    content += '<br>Subject: <input type="text" name="SubjectPart" size="40"><br>\n'
    content += 'HTML message: <textarea rows="25" cols="50" name="HtmlPart"></textarea><p>\n'

    content += 'Text message: <textarea rows="25" cols="50" name="TextPart"></textarea><p>\n' 
    content += '<input type="hidden" name="action" value="add_tmpl"><br>\n'
    content += '<input type="submit" name="Submit">'
    content += '<input type="reset">'
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

def validate_token(config,token):
  region = 'us-east-1'
  user_record = {}
  keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, config['admin_cognito_pool'])
  response = urlopen(keys_url)
  keys = json.loads(response.read())['keys']
  user_record['token'] = 'False'

  headers = jwt.get_unverified_headers(token)
  kid = headers['kid']
  # search for the kid in the downloaded public keys
  key_index = -1
  for i in range(len(keys)):
      if kid == keys[i]['kid']:
          key_index = i
          break
  if key_index == -1:
      log_error('Public key not found in jwks.json')
      return user_record

  # construct the public key
  public_key = jwk.construct(keys[key_index])

  # get the last two sections of the token,
  # message and signature (encoded in base64)
  message, encoded_signature = str(token).rsplit('.', 1)

  # decode the signature
  decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

  # verify the signature
  if not public_key.verify(message.encode("utf8"), decoded_signature):
      log_error('Signature verification failed')
      return user_record

  # since we passed the verification, we can now safely
  # use the unverified claims
  claims = jwt.get_unverified_claims(token)

  log_error('Token claims = '+json.dumps(claims))

  # additionally we can verify the token expiration
  if time.time() > claims['exp']:
      log_error('Token is expired')
      return user_record

  if claims['client_id'] != config['admin_cognito_client_id']:
      log_error('Token claims not valid for this application')
      return user_record
  
  user_record['username'] = claims['username']
  user_record['token'] = token

  return user_record

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
          url = config['cognito_auth_url']+"authorize?response_type=code&client_id="+config['admin_cognito_client_id']+"&redirect_uri="+config['content_url']
          log_error("Sending to "+url)

          return { 'statusCode': 301,
           'headers': {
              'Location': url,
              'Cache-Control': 'no-store'
           }
          }
  else:
    token = auth_record['token']

    if event['queryStringParameters']:
      log_error("Query string params were not None: "+str(event['queryStringParameters']))
      if 'action' in event['queryStringParameters']:
        if event['queryStringParameters']['action'] == 'add_user':
          content += print_add_user_form()
        elif event['queryStringParameters']['action'] == 'rm_user':
          content += print_rm_user_form()
        elif event['queryStringParameters']['action'] == 'email_tmpl':
          if 'tmpl' in event['queryStringParameters']:
            tmpl = event['queryStringParameters']['tmpl']
          else:
            tmpl = "default"
          content += print_email_templates(config,tmpl)
        elif event['queryStringParameters']['action'] == 'add_tmpl':
          content += print_email_templates(config,"")
        elif event['queryStringParameters']['action'] == 'email_coaches':
          content += '<h3>This has not been implemented as of yet</h3>'
        else:
          content += print_top_menu()
      else:
        content += print_top_menu()
    # Parse form params
    elif event['body']:
      # Parse the post parameters
      postparams = event['body']
      postparams = base64.b64decode(bytes(postparams,'UTF-8')).decode('utf-8')
      log_error('Got post params = '+postparams)
      raw_record = urllib.parse.parse_qs(postparams)
      for item in raw_record:
        if item != 'Submit':
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
          content += '<p><a href="?action=add_user">Back to Add User Page</a>'
          content += '<p><a href="">Back to Admin Page</a>'
        elif user_record['action'] == 'rm':
          response = rm_cognito_user(config,user_record)
          if not response['status']:
            content += "<h3>Unable to remove user from cognito pool - "+response['message']+"</h3>"
          else:
            content += '<h3>Successfully removed user from cognito pool</h3>\n'
          content += '<p><a href="?action=rm_user">Back to Remove User Page</a>'
          content += '<p><a href="">Back to Admin Page</a>'
        elif user_record['action'] == 'add_tmpl':
          del user_record['action']
          response = add_email_template(config,user_record)
          if not response['status']:
            content += "<h3>Unable to update template - "+response['message']+"</h3>\n"
          else:
            content += "<h3>Successfully updated email template<h3>\n"
          content += '<p><a href="?action=email_tmpl">Back to Edit Template</a>'
          content += '<p><a href="">Back to Admin Page</a>'
        elif user_record['action'] == 'update_tmpl':
          del user_record['action']
          response = update_email_template(config,user_record)
          if not response['status']:
            content += "<h3>Unable to update template - "+response['message']+"</h3>\n"
          else:
            content += "<h3>Successfully updated email template<h3>\n"
          content += '<p><a href="?action=email_tmpl">Back to Edit Template</a>'
          content += '<p><a href="">Back to Admin Page</a>'
        elif user_record['action'] == 'email':
          content += '<h4>This has not been implemented yet</h4>'
          content += '<p><a href="">Back to Admin Page</a>'
      else:
        content += print_top_menu()
    else:
      content += print_top_menu()

    content += "</body></html>"

  return {
    'statusCode': 200,
    'headers': {
      'Content-type': 'text/html',
      'Cache-Control': 'no-store, must-revalidate',
    },
    'body': content
  }
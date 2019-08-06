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

# Get Environment
environment = os.environ['ENVIRONMENT']

# Open DB connection
dynamodb = boto3.resource('dynamodb')

def log_error(msg):
  print(msg)

def get_config_data():
  client = boto3.client('ssm')
  environments = [ 'dev', 'prod']
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

  for env in config:
    for item in config[env]:
      log_error("For Env ["+env+"] Got config key = "+item+" value = "+config[env][item])

  return config

def start_html(config):
  # Build HTML content
  css = '<link rel="stylesheet" href="https://s3.amazonaws.com/'+config[environment]['s3_html_bucket']+'/admin/css/a2c.css" type="text/css" />'
  js = '<script src="https://s3.amazonaws.com/'+config[environment]['s3_html_bucket']+'/admin/javascript/thefirmu.js"></script>'
  content = "<html><head><title>A2C Portal</title>\n"
  content += css+'\n'
  content += js+'\n'
  content += '</head>\n'
  content += '<body>'
  content += '<div id="adminportal">\n'

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
  content += '<form method="post" action="/">'
  content += 'Enter Username: <input type="text" name="username"><p>\n'
  content += 'Choose Environment: <select name="environment">\n'
  content += '<option value="prod">Production</option>\n'
  content += '<option value="dev">Development</option>\n'
  content += '</select><p>\n'
  content += '<input type="hidden" name="action" value="rm">\n'
  content += '<input type="submit" name="Submit">'
  content += '</form>'

  return content

def print_add_user_form():
  content = '<h4>Add a user to The FirmU</h4>'
  content += '<form method="post" action="/">'
  content += 'Enter Username: <input type="text" name="username"><p>\n'
  content += 'Enter Email Address: <input type="email" name="email"><p>\n'
  content += 'Choose Environment: <select name="environment">\n'
  content += '<option value="prod">Production</option>\n'
  content += '<option value="dev">Development</option>\n'
  content += '</select><p>\n'
  content += '<input type="hidden" name="action" value="add">\n'
  content += '<input type="submit" name="Submit">'
  content += '</form>'

  return content

def get_coaches(config):
  t = dynamodb.Table(config[environment]['coaches_table_name'])

  # Get coaches list from Dynamo, need to add filtering to scan
  items = t.scan()
  if 'Items' in items:
    coaches = items['Items']
  else:
    coaches = []

  return coaches

def get_coach(config,coach):
  t = dynamodb.Table(config[environment]['coaches_table_name'])

  log_error("Key = "+coach)

  # Get coaches list from Dynamo, need to add filtering to scan
  coach_record = t.get_item(Key={ 'email': coach })

  log_error("Coach query returned = "+str(coach_record))

  if 'Item' in coach_record:
    return coach_record['Item']
  else:
    return False

def get_athlete(config,athlete):
  t = dynamodb.Table(config[environment]['table_name'])

  # Get coaches list from Dynamo, need to add filtering to scan
  athlete_record = t.get_item(Key={ 'username': athlete })

  log_error("Athlete query returned = "+str(athlete_record))
  
  if 'Item' in athlete_record:
    return athlete_record['Item']
  else:
    return False

def get_athletes(config):
  t = dynamodb.Table(config[environment]['table_name'])
  athletes = {}

  # Get coaches list from Dynamo, need to add filtering to scan
  items = t.scan()
  if 'Items' in items:
    for item in items['Items']:
      athletes[item['username']] = item

  return athletes

def add_email_template(config,template):
  retval = {}
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

def craft_email(config,name):
  ses = boto3.client('ses')
  tmpls = ses.list_templates()
  default = {}

  # Get coaches list from Dynamo, need to add filtering to scan
  coaches = get_coaches(config)

  content = '<form method="POST" action="/">\nSelect coaches from list: <select name="coaches" id="coaches" multiple>\n'
  for c in coaches:
    content += '<option value="'+c['email']+'">'+c['first']+' '+c['last']+' - '+c['school']+'</option>\n'

  content += '</select>\n'
  content += '<input type="button" name="Add" value="Add" onClick="addEmails(document.getElementById(\'coaches\'),\'toaddresses\')"><p><p>'
  content += 'To: <select id="toaddresses" name="toaddresses" multiple></select><p>\n'

  athletes = get_athletes(config)

  content += 'Select athletes to profile: <select name="athletes" id="athletes" multiple>\n'
  for a in athletes:
    content += '<option value="'+athletes[a]['username']+'">'
    if 'firstname' in athletes[a]:
      content += athletes[a]['firstname']
    content += ' '
    if 'lastname' in athletes[a]:
      content += athletes[a]['lastname']
    if 'yog' in athletes[a]:
      content += ' - '+athletes[a]['yog']
    content += '</option>\n'
  content += '</select>\n'
  content += '<input type="button" name="Add" value="Add" onClick="addEmails(document.getElementById(\'athletes\'),\'profiles\')"><p><p>'
  content += 'For: <select name="profiles" id="profiles" multiple></select><p><p>\n'

  content += 'Select a template to use: <select onChange="loadEmailTemplate(\'craft\',this.value)" name="TemplateName">'
  for tmpl in tmpls['TemplatesMetadata']:
    content += '<option value='+tmpl['Name']
    if tmpl['Name'] == name:
      template = ses.get_template(TemplateName=tmpl['Name'])
      content += ' selected '
      default['TemplateName'] = template['Template']['TemplateName']
      default['SubjectPart'] = template['Template']['SubjectPart']
      default['HtmlPart'] = template['Template']['HtmlPart']
      default['TextPart'] = template['Template']['TextPart']
    content += '>'+tmpl['Name']+'</option>\n'
  content += '</select>'

  content += '<p>Subject: <input type="text" name="SubjectPart" size="40" value="'+default['SubjectPart']+'"><p>\n'
  content += 'HTML message: <textarea rows="25" cols="50" name="HtmlPart">'
  content += default['HtmlPart']
  content += '</textarea><p>\n'

  content += 'Text message: <textarea rows="25" cols="50" name="TextPart">'
  content += default['TextPart']
  content += '</textarea><p>\n'

  content += '<input type="hidden" name="action" value="send_email"><br>\n'
  content += '<input type="submit" name="submit" value="Send Email">\n'
  content += '</form>\n'

  return content
  
def send_email_template(config,record):
  client = boto3.client('ses')

  retval = {}
  replyto = []
  source = 'admin@thefirmu.org'
  replyto.append('admin@thefirmu.org')
  toaddresses = []
  profiles = []
  dest = {}
  dest['ToAddresses'] = []
  template_data = {}
  for to in record['toaddresses']:
    toaddresses.append(to)
  profiles.append(record['profiles'])
  template = record['TemplateName']

  athletes = get_athletes(config)
  log_error("Athletes = "+str(athletes))

  for to in toaddresses:
    dest['ToAddresses'].append(to)
    coach = get_coach(config,to)

    for athlete in profiles:
      log_error("Athlete profile: "+str(athletes[athlete]))
      for item in athletes[athlete]:
        template_data[item] = athletes[athlete][item]
      template_data['coachname'] = coach['first']+' '+coach['last']
      template_data['school'] = coach['school']

      try:
        response = client.send_templated_email(Source=source, Destination=dest, ReplyToAddresses=replyto,Template=template,ConfigurationSetName=config[environment]['ses_configuration_set'],TemplateData=json.dumps(template_data))
        retval['status'] = True
        retval['message'] = "Successfully sent email"
      except ClientError as e:
        log_error("response = "+json.dumps(e.response))
        log_error("Error is "+e.response['Error']['Message'])
        retval['status'] = False
        retval['message'] = e.response['Error']['Message']

  return retval

def update_email_template(config,template):
  retval = {}
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
    content += '<form method="POST" action="/">\nSelect a template to edit: <select onChange="loadEmailTemplate(\'print\',this.value)" name="TemplateName">'

    default = {}
    # display template list
    for tmpl in tmpls['TemplatesMetadata']:
      content += '<option value='+tmpl['Name']
      if tmpl['Name'] == name:
        template = client.get_template(TemplateName=tmpl['Name'])
        content += ' selected '
        default['TemplateName'] = template['Template']['TemplateName']
        default['SubjectPart'] = template['Template']['SubjectPart']
        default['HtmlPart'] = template['Template']['HtmlPart']
        default['TextPart'] = template['Template']['TextPart']
      content += '>'+tmpl['Name']+'</option>\n'
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
  environment = record['environment']

  # Create cognito pool user
  try:
    response = cognito.admin_create_user(
      UserPoolId=config[environment]['cognito_pool'],
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
  environment = record['environment']

  # Remove cognito pool user
  try:
    response = cognito.admin_delete_user(
      UserPoolId=config[environment]['cognito_pool'],
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
  if 'environment' in record:
    environment = record['environment']

  t = dynamodb.Table(config[environment]['table_name'])

  retval = {}

  # Delete environment item
  if 'environment' in record:
    del record['environment']

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
  keys_url = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'.format(region, config[environment]['admin_cognito_pool'])
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

  if claims['aud'] != config[environment]['admin_cognito_client_id']:
      log_error('Token claims not valid for this application')
      return user_record
  
  if 'cognito:username' in claims:
    user_record['username'] = claims['cognito:username']
  elif 'username' in claims:
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
  auth_header = base64.b64encode(bytes(config[environment]['admin_cognito_client_id']+':'+config[environment]['admin_cognito_client_secret_hash'],'UTF-8'))
  data = {
    "grant_type": "authorization_code",
    "code": code,
    "client_id": config[environment]['admin_cognito_client_id'],
    "redirect_uri": redirect_uri
  }
  r = requests.post(config[environment]['cognito_auth_url']+'token',auth=auth_header,data=data)

  res = r.json()

  return res['id_token']

def mgmt_handler(event, context):
  token = False
  action = "False"
  user_record = {}

  log_error("Event = "+json.dumps(event))

  config = get_config_data()

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
          url = config[environment]['cognito_auth_url']+"authorize?response_type=code&client_id="+config[environment]['admin_cognito_client_id']+"&redirect_uri="+config[environment]['admin_content_url']
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
          content += '<p><a href="/">Back to Admin Page</a>'
        elif event['queryStringParameters']['action'] == 'rm_user':
          content += print_rm_user_form()
          content += '<p><a href="/">Back to Admin Page</a>'
        elif event['queryStringParameters']['action'] == 'email_tmpl':
          if 'tmpl' in event['queryStringParameters']:
            tmpl = event['queryStringParameters']['tmpl']
          else:
            tmpl = "default"
          content += print_email_templates(config,tmpl)
          content += '<p><a href="/">Back to Admin Page</a>'
        elif event['queryStringParameters']['action'] == 'add_tmpl':
          content += print_email_templates(config,"")
          content += '<p><a href="/">Back to Admin Page</a>'
        elif event['queryStringParameters']['action'] == 'email_coaches':
          if 'tmpl' in event['queryStringParameters']:
            tmpl = event['queryStringParameters']['tmpl']
          else:
            tmpl = "default"
          content += craft_email(config,tmpl)
          content += '<p><a href="/">Back to Admin Page</a>'
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
      log_error('Raw Record = '+str(raw_record))
      for item in raw_record:
        if item != 'Submit':
          user_record[item] = raw_record[item][0]
        if item == 'toaddresses':
          user_record[item] = raw_record[item]

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
          content += '<p><a href="/">Back to Admin Page</a>'
        elif user_record['action'] == 'rm':
          response = rm_cognito_user(config,user_record)
          if not response['status']:
            content += "<h3>Unable to remove user from cognito pool - "+response['message']+"</h3>"
          else:
            content += '<h3>Successfully removed user from cognito pool</h3>\n'
          content += '<p><a href="?action=rm_user">Back to Remove User Page</a>'
          content += '<p><a href="/">Back to Admin Page</a>'
        elif user_record['action'] == 'add_tmpl':
          del user_record['action']
          response = add_email_template(config,user_record)
          if not response['status']:
            content += "<h3>Unable to update template - "+response['message']+"</h3>\n"
          else:
            content += "<h3>Successfully updated email template<h3>\n"
          content += '<p><a href="?action=email_tmpl">Back to Edit Template</a>'
          content += '<p><a href="/">Back to Admin Page</a>'
        elif user_record['action'] == 'update_tmpl':
          del user_record['action']
          response = update_email_template(config,user_record)
          if not response['status']:
            content += "<h3>Unable to update template - "+response['message']+"</h3>\n"
          else:
            content += "<h3>Successfully updated email template</h3>\n"
          content += '<p><a href="?action=email_tmpl">Back to Edit Template</a>'
          content += '<p><a href="/">Back to Admin Page</a>'
        elif user_record['action'] == 'send_email':
          response = send_email_template(config,user_record)
          if not response['status']:
            content += '<h3>Unable to send email template</h3>\n'
          else:
            content += '<h3>'+response['message']+'</h3>\n'
          content += '<p><a href="?action=email_coaches">Back to Email Coaches</a>'
          content += '<p><a href="/">Back to Admin Page</a>'
      else:
        content += print_top_menu()
    else:
      content += print_top_menu()

    content += "</div></body></html>"

  return {
    'statusCode': 200,
    'headers': {
      'Content-type': 'text/html',
      'Cache-Control': 'no-store, must-revalidate',
    },
    'body': content
  }
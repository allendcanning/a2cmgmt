#!/usr/local/bin/python3

import json
import os.path
import csv
from optparse import OptionParser
import boto3
from botocore.exceptions import ClientError

# Functions used
def Usage():
  parser.print_help()

def log_error(msg):
    print(msg)

def get_config_data(session,environment):
  client = session.client('ssm')

  config = {}

  ssmpath="/a2c/"+environment+"/coaches_table_name"
  response = client.get_parameter(Name=ssmpath,WithDecryption=False)
  config['coaches_table_name'] =response['Parameter']['Value'] 

  return config

def put_coach(session,config,record):
  client = session.resource('dynamodb')

  t = client.Table(config['coaches_table_name'])

  try:
    t.put_item(Item=record)
    log_error("Successfully put : "+record['email'])
  except ClientError as e:
    log_error("response = "+json.dumps(e.response))
    log_error("Error is "+e.response['Error']['Message'])

# Begin of main section
parser = OptionParser()
parser.add_option("-a", "--aws", dest="aws",help="AWS Profile")
parser.add_option("-f", "--file", dest="file",help="Coaches List File")
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

if not options.file:
  Usage()
  exit(1)

if os.path.isfile(options.file):
  config = get_config_data(session,environment)

  data = {}
  with open(options.file, newline='')  as csvfile:
    csvline = csv.DictReader(csvfile,dialect='excel')
    for row in csvline:
      data['email'] = row['Email']
      data['first'] = row['First Name']
      data['last'] = row['Last Name']
      data['school'] = row['School']
      data['division'] = row['Division']
      data['conference'] = row['Conference']
      data['sport'] = row['Sport']
      data['gender'] = row['Gender']
      retval = put_coach(session,config,data)
else:
  log_error("File ("+options.file+") does not exist -- exiting...")
  exit(1)
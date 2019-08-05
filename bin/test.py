#!/usr/local/bin/python3 

import boto3
import botocore

# Set "running_locally" flag if you are running the integration test locally
running_locally = True
region = "us-east-1"
function_name = "mgmtPortalFunction"

if running_locally:

    # Create Lambda SDK client to connect to appropriate Lambda endpoint
    lambda_client = boto3.client('lambda',
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
    lambda_client = boto3.client('lambda')

# Invoke your Lambda function as you normally usually do. The function will run
# locally if it is configured to do so
response = lambda_client.invoke(FunctionName=function_name)

# Verify the response
print("Syntax...")
if 'StatusCode' in response:
  if response['StatusCode'] > 200 and response['StatusCode'] < 300:
    print("ok")

# check GET responses

# check POST responses

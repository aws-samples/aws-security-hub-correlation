import json
import boto3
import logging
import os
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from decimal import *


logger=logging.getLogger()
logger.setLevel(logging.INFO)

ddb = boto3.resource('dynamodb')
DYNAMODB_TABLE = os.environ['DYNAMODB_TABLE']
DYNAMODB_TTL = os.environ['DYNAMODB_TTL']

def add_sh_dynamodb_entry (ddbpayload):
    logger.info('Adding new Security Hub as DynamoDB entry...')
    ddbtable = ddb.Table(DYNAMODB_TABLE)
    try:
        response = ddbtable.put_item(
            Item=ddbpayload
        )
        logger.info('Successfully added DynamoDB entry.')
    except ClientError as error_handle:
        logger.error(error_handle.response['Error']['Code'])

def format_dynamodb_payload (event):
    logger.info('Formatting Security Hub entry for DynamoDB...')
    SourceUrl = ""
    if "SourceUrl" in event['detail']['findings'][0]:
        # Inspector does not have SourceUrl field
        SourceUrl = event['detail']['findings'][0]['SourceUrl']        
    ddbpayload = {
        "SchemaVersion": event['detail']['findings'][0]['SchemaVersion'],
        "Title": event['detail']['findings'][0]['Title'],
        "AwsAccountId": event['detail']['findings'][0]['AwsAccountId'],
        "CreatedAt": event['detail']['findings'][0]['CreatedAt'],
        "UpdatedAt": event['detail']['findings'][0]['UpdatedAt'],
        "Description": event['detail']['findings'][0]['Description'],
        "Types": event['detail']['findings'][0]['FindingProviderFields']['Types'][0],
        "SourceUrl": SourceUrl,
        "ProductArn": event['detail']['findings'][0]['ProductArn'],
        "ProductName": event['detail']['findings'][0]['ProductName'],
        "GeneratorId": event['detail']['findings'][0]['GeneratorId'],
        "Id": event['detail']['findings'][0]['Id'],
        "Region": event['detail']['findings'][0]['Region'],
        "CompanyName": event['detail']['findings'][0]['CompanyName'],
        "ResourceType": event['detail']['findings'][0]['Resources'][0]['Type'],
        "ResourceRegion": event['detail']['findings'][0]['Resources'][0]['Region'],
        "ResourceId": event['detail']['findings'][0]['Resources'][0]['Id'],
        "Severity": event['detail']['findings'][0]['Severity']['Label'],
        "ExpDate": int((datetime.now()+timedelta(days=int(DYNAMODB_TTL))).timestamp())
    }
    return ddbpayload

def lambda_handler(event, context):
    ddbpayload = format_dynamodb_payload (event)
    add_sh_dynamodb_entry (ddbpayload)
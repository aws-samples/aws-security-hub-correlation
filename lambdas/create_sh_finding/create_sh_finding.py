import json
import boto3
import logging
import os
from dateutil import parser
import hashlib
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key,  Attr

logger=logging.getLogger()
logger.setLevel(logging.INFO)

DYNAMODB_TABLE = os.environ['DYNAMODB_TABLE']
DYNAMODB_GSI_TYPE = os.environ['DYNAMODB_GSI']

securityhub = boto3.client('securityhub')
ddb = boto3.resource('dynamodb')

def create_securityhub_finding (sh_payload):
    findings = []
    findings.append(
        sh_payload
    )
    if len(findings) > 0:
        logger.info('Creating custom Security Hub finding...')
        try:
            response = securityhub.batch_import_findings(
            Findings=findings
            )
            logger.info("Successfully imported {} Security Hub findings".format(response['SuccessCount']))
        except ClientError as error_handle:
            if error_handle.response['Error']['Code'] == 'AccessDeniedException':
                logger.warning('Check permissions to import Security Hub findings.')
            else:
                logger.error(error_handle.response['Error']['Code'])
        if response['FailedCount'] > 0:
            logger.info("Failed to import {} Security Hub findings".format(response['FailedCount']))
    else:
        logger.info('No DynamoDB Security Hub matches found...')

def create_securityhub_payload(dynamodb_match):
    logger.info('Creating Security Hub finding payload...')
    detector_id = hashlib.md5(json.dumps(dynamodb_match['Items'][0]['Types']).encode()).hexdigest()
    finding_id = hashlib.md5(json.dumps(dynamodb_match['Items'][0]['ResourceId']).encode()).hexdigest()
    convert_list = [str(element) for element in dynamodb_match['SourceUrlList']]
    SourceUrlString = ",".join(convert_list)
    sh_payload = {
        "SchemaVersion": dynamodb_match['Items'][0]['SchemaVersion'],
        "Title": dynamodb_match['SH_Title'],
        "AwsAccountId": dynamodb_match['Items'][0]['AwsAccountId'],
        "CreatedAt": dynamodb_match['Items'][0]['CreatedAt'],
        "UpdatedAt": dynamodb_match['Items'][0]['UpdatedAt'],
        "Description": dynamodb_match['Items'][0]['Description'],
        "SourceUrl": dynamodb_match['Items'][0]['SourceUrl'],
        "FindingProviderFields": {
            "Severity": {
                "Label": "CRITICAL",
                "Original": dynamodb_match['Items'][0]['Severity']
            },
            "Types": [dynamodb_match['Items'][0]['Types']]
        },
        "GeneratorId": 'arn:aws:securityhub:' + dynamodb_match['Items'][0]['Region'] + ':' + dynamodb_match['Items'][0]['AwsAccountId'] + ':detector/' + detector_id,
        "Id": 'arn:aws:securityhub:' + dynamodb_match['Items'][0]['Region'] + ':' + dynamodb_match['Items'][0]['AwsAccountId'] + ':detector/' + detector_id + '/finding/'+ finding_id,
        "ProductArn": 'arn:aws:securityhub:' + dynamodb_match['Items'][0]['Region'] + ':' + dynamodb_match['Items'][0]['AwsAccountId'] + ':product/' + dynamodb_match['Items'][0]['AwsAccountId'] + '/default',
        "Resources": [{
            'Type': 'AwsEc2Instance',
            'Region': dynamodb_match['Items'][0]['Region'],
            'Id': dynamodb_match['Items'][0]['ResourceId']
        }],
        "Note": {
            "Text": SourceUrlString,
            "UpdatedBy": 'arn:aws:securityhub:' + dynamodb_match['Items'][0]['Region'] + ':' + dynamodb_match['Items'][0]['AwsAccountId'] + ':product/' + dynamodb_match['Items'][0]['AwsAccountId'] + '/default',
            "UpdatedAt": dynamodb_match['Items'][0]['UpdatedAt']
        }
    }
    create_securityhub_finding (sh_payload)

def check_inspector_cve(sh_resource, ddbtable):
    try:
        inspector_cve_payload = ddbtable.scan(
        FilterExpression=Attr('ResourceId').eq(sh_resource) & Attr('ProductName').eq('Inspector') & Attr('Severity').eq('CRITICAL')
        )
        for item in inspector_cve_payload['Items']:
            while 'LastEvaluatedKey' in item:
                inspector_cve_payload_paginate = ddbtable.scan(        
                    FilterExpression=Attr('ResourceId').eq(sh_resource) & Attr('ProductName').eq('Inspector') & Attr('Severity').eq('CRITICAL'), 
                    ExclusiveStartKey=inspector_cve_payload_paginate['LastEvaluatedKey']
                    )
                for item in inspector_cve_payload_paginate['Items']:
                    if item['Count'] >= 3:
                        logger.info('Found {} Critical Inspector CVEs for {}.'.format(inspector_cve_payload['Count'],sh_resource))
                        return inspector_cve_payload
                    else:
                        logger.info('Minimum Critical Inspector CVE threshhold not met for {}.'.format(sh_resource))
        if inspector_cve_payload['Count'] >= 3:
            logger.info('Found {} Critical Inspector CVEs for {}.'.format(inspector_cve_payload['Count'],sh_resource))
            return inspector_cve_payload
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def check_gd_backdoor(sh_resource, ddbtable):
    gd_backdoor_list = [
        'TTPs/Command and Control/Backdoor:EC2-DenialOfService.Tcp',
        'TTPs/Command and Control/Backdoor:EC2-DenialOfService.Udp',
        'TTPs/Command and Control/Backdoor:EC2-DenialOfService.Dns',
        'TTPs/Command and Control/Backdoor:EC2-DenialOfService.UdpOnTcpPorts',
        'TTPs/Command and Control/Backdoor:EC2-DenialOfService.UnusualProtocol',
        'TTPs/Command and Control/Backdoor:EC2-Spambot',
        'TTPs/Command and Control/Backdoor:EC2-C&CActivity.B!DNS',
        'TTPs/Command and Control/Backdoor:EC2-C&CActivity.B'
        ]
    try:
        for item in gd_backdoor_list:
            backdoor_payload = ddbtable.query(
            IndexName= DYNAMODB_GSI_TYPE,
            KeyConditionExpression=Key('ResourceId').eq(sh_resource) & Key('Types').eq(item)
            )
            if backdoor_payload['Count'] >= 1:
                logger.info('Found GuardDuty EC2 backdoor finding {} for {}.'.format(item, sh_resource))
                return backdoor_payload
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def check_ssh_brute_force(sh_resource, ddbtable):
    ssh_brute_force = 'TTPs/Initial Access/UnauthorizedAccess:EC2-SSHBruteForce'
    try:
        ssh_brute_force_payload = ddbtable.query(
        IndexName= DYNAMODB_GSI_TYPE,
        KeyConditionExpression=Key('ResourceId').eq(sh_resource) & Key('Types').eq(ssh_brute_force)
        )
        if ssh_brute_force_payload['Count'] >= 1:
            logger.info('Found GuardDuty SSH Brute force for {}.'.format(sh_resource))
            return ssh_brute_force_payload
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def check_winrm_brute_force(sh_resource, ddbtable):
    ssh_brute_force = 'TTPs/Impact/Impact:EC2-WinRMBruteForce'
    try:
        winrm_brute_forice_payload = ddbtable.query(
        IndexName= DYNAMODB_GSI_TYPE,
        KeyConditionExpression=Key('ResourceId').eq(sh_resource) & Key('Types').eq(ssh_brute_force)
        )
        if winrm_brute_forice_payload['Count'] >= 1:
            logger.info('Found GuardDuty Win RM Bruteforce for {}.'.format(sh_resource))
            return winrm_brute_forice_payload
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def check_rdp_brute_force(sh_resource, ddbtable):
    rdp_brute_force = 'TTPs/Initial Access/UnauthorizedAccess:EC2-RDPBruteForce'
    try:
        rdp_brute_force_payload = ddbtable.query(
            IndexName= DYNAMODB_GSI_TYPE,
            KeyConditionExpression=Key('ResourceId').eq(sh_resource) & Key('Types').eq(rdp_brute_force)
        )
        if rdp_brute_force_payload ['Count'] >= 1:
            logger.info('Found GuardDuty RDP Brute force for {}.'.format(sh_resource))
            return rdp_brute_force_payload
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def check_network_unusual(sh_resource, ddbtable):
    gd_network_list = [
        'Unusual Behaviors/VM/Behavior:EC2-NetworkPortUnusual',
        'Unusual Behaviors/VM/Behavior:EC2-TrafficVolumeUnusual'
        ]
    try:
        for item in gd_network_list:
            network_payload = ddbtable.query(
            IndexName= DYNAMODB_GSI_TYPE,
            KeyConditionExpression=Key('ResourceId').eq(sh_resource) & Key('Types').eq(item)
            )
            if network_payload['Count'] >= 1:
                logger.info('Found GuardDuty Unusual Networking match {} for {}.'.format(item, sh_resource))
                return network_payload
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def check_sh_ec2_public(sh_resource, ddbtable):
    sh_finding_type = 'Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices'
    sh_public_ip_string = 'aws-foundational-security-best-practices/v/1.0.0/EC2.9'
    sh_unrestrict_sg_string = 'aws-foundational-security-best-practices/v/1.0.0/EC2.18'
    try:
        sh_public_payload = ddbtable.query(
        IndexName= DYNAMODB_GSI_TYPE,
        KeyConditionExpression=Key('ResourceId').eq(sh_resource) & Key('Types').eq(sh_finding_type)
        )
        if sh_public_payload['Count'] >= 1:
            if sh_public_ip_string in sh_public_payload['Items'][0]['GeneratorId']:
                logger.info('Found Security Hub finding for public IPv4 address for {}.'.format(sh_resource))
                return sh_public_payload
            elif sh_unrestrict_sg_string in sh_public_payload['Items'][0]['GeneratorId']:
                logger.info('Found Security Hub finding for Security Group allowing unrestricted incoming ports for {}.'.format(sh_resource))
                return sh_public_payload
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def check_sh_unrestrict_sg(sh_resource, ddbtable):
    sh_unrestrict_sg = 'Software and Configuration Checks/Industry and Regulatory Standards/AWS-Foundational-Security-Best-Practices'
    sh_unrestrict_sg_string = 'aws-foundational-security-best-practices/v/1.0.0/EC2.18'
    try:
        sh_unrestrict_sg_payload = ddbtable.query(
        IndexName= DYNAMODB_GSI_TYPE,
        KeyConditionExpression=Key('ResourceId').eq(sh_resource) & Key('Types').eq(sh_unrestrict_sg)
        )
        if sh_unrestrict_sg_payload['Count'] >= 1:
            if sh_unrestrict_sg_string in sh_unrestrict_sg_payload['Items'][0]['GeneratorId']:
                logger.info('Found Security Hub finding for Security Group allowing unrestricted incoming ports for {}.'.format(sh_resource))
                return sh_unrestrict_sg_payload
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def check_ssh_brute_force(sh_resource, ddbtable):
    ssh_brute_force = 'TTPs/Initial Access/UnauthorizedAccess:EC2-SSHBruteForce'
    try:
        ssh_brute_force_payload = ddbtable.query(
        IndexName= DYNAMODB_GSI_TYPE,
        KeyConditionExpression=Key('ResourceId').eq(sh_resource) & Key('Types').eq(ssh_brute_force)
        )
        if ssh_brute_force_payload['Count'] >= 1:
            logger.info('Found GuardDuty SSH Brute force for {}.'.format(sh_resource))
            return ssh_brute_force_payload
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def check_macie_sensitive_data(sh_resource, ddbtable):
    macie_sensitive_data_findings = [
        'Sensitive Data Identifications/PII/SensitiveData:S3Object-Credentials',
        'Sensitive Data Identifications/PII/SensitiveData:S3Object-CustomIdentifier',
        'Sensitive Data Identifications/PII/SensitiveData:S3Object-Financial',
        'Sensitive Data Identifications/PII/SensitiveData:S3Object-Multiple',
        'Sensitive Data Identifications/PII/SensitiveData:S3Object-Personal'
        ]
    try:
        for item in macie_sensitive_data_findings:
            macie_sensitive_payload = ddbtable.query(
            IndexName= DYNAMODB_GSI_TYPE,
            KeyConditionExpression=Key('ResourceId').eq(sh_resource) & Key('Types').eq(item)
            )
            if macie_sensitive_payload['Count'] >= 1:
                logger.info('Found Macie finding for S3 bucket with sensitive data {}.'.format(sh_resource))
                return macie_sensitive_payload
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def check_s3_exfil(sh_resource, ddbtable):
    s3_exfil_unusual = 'TTPs/Exfiltration:S3-ObjectRead.Unusual'
    s3_exfil_malicious_ip = 'TTPs/Exfiltration:S3-MaliciousIPCaller'
    try:
        s3_exfil_payload = ddbtable.query(
            IndexName= DYNAMODB_GSI_TYPE,
            KeyConditionExpression=Key('ResourceId').eq(sh_resource) & Key('Types').eq(s3_exfil_unusual)
        )
        s3_exfil_malicious_ip_payload = ddbtable.query(
            IndexName= DYNAMODB_GSI_TYPE,
            KeyConditionExpression=Key('ResourceId').eq(sh_resource) & Key('Types').eq(s3_exfil_malicious_ip)
        )
        if s3_exfil_payload ['Count'] >= 1:
            logger.info('Found GuardDuty finding with unusual reads on S3 bucket {}.'.format(sh_resource))
            return s3_exfil_payload
        elif s3_exfil_malicious_ip_payload ['Count'] >= 1:
            logger.info('Found GuardDuty finding for actions from malicious IPs on S3 bucket {}.'.format(sh_resource))
            return s3_exfil_malicious_ip_payload
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def network_correlation(sh_resource, ddbtable):
    try:
        logger.info('CHECK#1: Security Hub exposed IP or unrestricted SG & GuardDuty Finding for Unusual Network port and Brute force attack for {}...'.format(sh_resource))
        check_sh_ec2_public_payload = check_sh_ec2_public(sh_resource, ddbtable)
        network_payload = check_network_unusual(sh_resource, ddbtable)
        ssh_brute_force_payload = check_ssh_brute_force(sh_resource, ddbtable)
        winrm_brute_forice_payload = check_winrm_brute_force(sh_resource, ddbtable)
        rdp_brute_force_payload = check_rdp_brute_force(sh_resource, ddbtable)
        if ((check_sh_ec2_public_payload) and network_payload and (ssh_brute_force_payload or rdp_brute_force_payload or winrm_brute_forice_payload)):
            logger.info('Match found for Security Hub exposed IP or unrestricted SG & GuardDuty Brute force and Unusual Network Port for {}.'.format(sh_resource))
            SH_title = {"SH_Title":'Unusual Network port and Brute force found for possibly exposed EC2 instance {}'.format(sh_resource)}
            SourceUrls = []
            SourceUrls.append(check_sh_ec2_public_payload['Items'][0]['SourceUrl'])
            SourceUrls.append(network_payload['Items'][0]['SourceUrl'])
            SourceUrlList = {"SourceUrlList": SourceUrls}
            network_payload.update(SourceUrlList)
            network_payload.update(SH_title)
        else:
            logger.info('No matches found for Security Hub exposed IP or SG & GuardDuty Unusual Network and RDS/SSH Brute force for {}.'.format(sh_resource))
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def macie_correlation(sh_resource, ddbtable):
    try:
        logger.info('CHECK #2: S3 exfiltration on S3 bucket with senstiive data {}...'.format(sh_resource))
        macie_payload = check_macie_sensitive_data(sh_resource, ddbtable)
        s3_exfil_payload = check_s3_exfil(sh_resource, ddbtable)
        if (macie_payload and s3_exfil_payload):
            logger.info('Match found for S3 exfiltration on S3 bucket conataining sensitive data {}.'.format(sh_resource))
            SH_title = {"SH_Title":'S3 data exfiltration observed on S3 bucket {} containing sensitive data'.format(sh_resource)}
            s3_exfil_payload.update(SH_title)
            SourceUrls = []
            SourceUrls.append(macie_payload['Items'][0]['SourceUrl'])
            SourceUrls.append(s3_exfil_payload['Items'][0]['SourceUrl'])
            SourceUrlList = {"SourceUrlList": SourceUrls}
            s3_exfil_payload.update(SourceUrlList)
            create_securityhub_payload(s3_exfil_payload)
        else:
            logger.info('No matches found for GuardDuty S3 exfiltration and Macie S3 buckets with senstiive data.')
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def backdoor_correlation(sh_resource, ddbtable):
    try:
        logger.info('CHECK #3: GuardDuty EC2 backdoor and Inspector Critical CVEs for {}...'.format(sh_resource))
        gd_backdoor_payload = check_gd_backdoor(sh_resource, ddbtable)
        inspector_cve_payload = check_inspector_cve(sh_resource, ddbtable)
        if (gd_backdoor_payload and inspector_cve_payload):
            logger.info('Match found for GuardDuty EC2 backdoor and 3 Inspector Critical CVEs for {}.'.format(sh_resource))
            SH_title = {"SH_Title":'GuardDuty EC2 Backdoor and Critical CVEs found for {}.'.format(sh_resource)}
            gd_backdoor_payload.update(SH_title)
            SourceUrls = []
            SourceUrls.append(gd_backdoor_payload['Items'][0]['SourceUrl'])
            SourceUrls.append(inspector_cve_payload['Items'][0]['SourceUrl'])
            SourceUrlList = {"SourceUrlList": SourceUrls}
            gd_backdoor_payload.update(SourceUrlList)
            create_securityhub_payload(gd_backdoor_payload)
        else:
            logger.info('No matches found for GuardDuty EC2 backdoor and 3 Inspector Critical CVEs for {}.'.format(sh_resource))
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def find_sh_correlation_match(event):
    sh_resource = event['Records'][0]['dynamodb']['NewImage']['ResourceId']['S']
    logger.info('Searching DynamoDB entry for {}...'.format(sh_resource))
    ddbtable = ddb.Table(DYNAMODB_TABLE)
    try:
        network_correlation(sh_resource, ddbtable)
        macie_correlation(sh_resource, ddbtable)
        backdoor_correlation(sh_resource, ddbtable)
    except ClientError as error_handle:
        logger.error(error_handle.dynamodb_match['Error']['Code'])

def lambda_handler(event, context):
    find_sh_correlation_match(event)
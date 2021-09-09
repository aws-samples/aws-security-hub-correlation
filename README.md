# Security Hub Correlation CDK Project!

The CDK Typescript project will deploy out the AWS components required to correlate Security Hub Findings from multiple AWS Security Services to generate a new Security Hub Finding to indicate a higher chance of a compromise or breach. 

1. A Security Hub Finding is generated from:
    - Security Hub Operational Foundational Security Best Practices Standard
    - GuardDuty
    - Macie
    - Inspector
2. CloudWatch EventBridge is triggered when specific Security Hub Findings are generated to invoke the **create_ddb_sh_entry** Lambda Function.
3. The **create_ddb_sh_entry** lambda will create a new entry for that Security Hub Finding to a DynamoDB table called **security-hub-correlation-table**.
4. DynamoDB Streams are enabled and any net new item will invoke the **create_sh_finding** Lambda function.
5. The **create_sh_finding** lambda will check for matches across multiple Security Hub findings against a single AWS resource. If a match is found, a new Security Hub finding will be generated with an appropriate Severity label.
6. DynamoDB Configured to use TTL and Global Secondary Indexes (GSI). 
    - DynamoDB TTL is 30 days by default but can be changed
    - DynamoDB Global Secondary Index (GSI) to search Security Hub Finding Types

## Build

To build this app, you need to be in the project root folder. Then run the following:

npm install -g aws-cdk
npm install
npm run build

    $ npm install -g aws-cdk
    <installs AWS CDK>

    $ npm install
    <installs appropriate packages>

    $ npm run build
    <build TypeScript files>

## Deploy

    $ cdk bootstrap aws://<INSERT_AWS_ACCOUNT>/<INSERT_REGION>
    <build S3 bucket to store files to perform deployment>

    $ cdk deploy
    <deploys the cdk project into the authenticated AWS account>

## CDK Toolkit

The [`cdk.json`](./cdk.json) file in the root of this repository includes
instructions for the CDK toolkit on how to execute this program.

After building your TypeScript code, you will be able to run the CDK toolkits commands as usual:

    $ cdk ls
    <list all stacks in this program>

    $ cdk synth
    <generates and outputs cloudformation template>

    $ cdk deploy
    <deploys stack to your account>

    $ cdk diff
    <shows diff against deployed stack>

## Correlations
There are a total of 3 separate checks that each have their own logic to determine if a new AWS Security Hub finding should be created. In order for 

1. GuardDuty EC2 Backdoor & 3 Critical Inspector Common Vulnerabilities and Exposures (CVE)
    - Must have any one of:
        - [GuardDuty EC2 Backdoor](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html)
    - Must have at least 3:
        - [Inspector CRITICAL CVE](https://docs.aws.amazon.com/inspector/latest/userguide/inspector_cves.html)
2. GuardDuty S3 Data Exfil & Macie S3 bucket with sensitive data
    - Must have any one of:
        - [GuardDuty S3 Data Exfil](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html)
    - Must have any one of:
        - [Macie Sensitive Data](https://docs.aws.amazon.com/macie/latest/user/findings-types.html#findings-sensitive-data-types)
3. GuardDuty Network Port Unusual & Brute Force & Security Hub EC2 Public
    - Must have any one of:
        - [GuardDuty Network Port Unusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#behavior-ec2-networkportunusual)
        - [GuardDuty Traffic Volume Unusual](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#behavior-ec2-trafficvolumeunusual)
    - Must have any one of:
        - [GuardDuty WinRMBrute Force](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#impact-ec2-winrmbruteforce)
        - [GuardDuty RDP Force](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-rdpbruteforce)
        - [GuardDuty SSH Force](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html#unauthorizedaccess-ec2-sshbruteforce)
    - Must have both:
        - [Security Hub Public IP](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-ec2-9)
        - [Security Hub Unauthorized Ports](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-ec2-18)

## Security
See [CONTRIBUTING](https://github.com/aws-samples/aws-security-hub-correlation/blob/main/CONTRIBUTING.md#security-issue-notifications) for more information.

## License
This library is licensed under the MIT-0 License. See the LICENSE file.
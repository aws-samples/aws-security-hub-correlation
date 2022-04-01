import * as cdk from '@aws-cdk/core';
import * as iam from '@aws-cdk/aws-iam';
import { EventBus, Rule } from '@aws-cdk/aws-events';
import { LambdaFunction } from '@aws-cdk/aws-events-targets';
import { Function, Runtime, Code, StartingPosition } from '@aws-cdk/aws-lambda';
import { join } from 'path';
import { Table, AttributeType, TableEncryption, StreamViewType, BillingMode } from '@aws-cdk/aws-dynamodb';
import { Key } from '@aws-cdk/aws-kms';
import { DynamoEventSource } from '@aws-cdk/aws-lambda-event-sources';

export class SecurityhubCorrelationBlogStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // DynamoDB Table for SecurityHub Findings
    const DynamoDBencryptionKey = new Key(this, 'DynamoDBencryptionKey', {
      enableKeyRotation: true
    });

    const dynamoTable = new Table(this, 'items', {
      partitionKey: {
        name: 'Id',
        type: AttributeType.STRING
      },
      sortKey: {
        name: 'ResourceId',
        type: AttributeType.STRING
      },
      stream: StreamViewType.NEW_IMAGE,
      encryption: TableEncryption.CUSTOMER_MANAGED, 
      encryptionKey: DynamoDBencryptionKey,
      timeToLiveAttribute: 'ExpDate',
      billingMode: BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      tableName: 'security_hub_correlation_table',
      // The default removal policy is RETAIN, which means that cdk destroy will not attempt to delete
      // the new table, and it will remain in your account until manually deleted. By setting the policy to 
      // DESTROY, cdk destroy will delete the table (even if it has data in it)
      removalPolicy: cdk.RemovalPolicy.DESTROY, // NOT recommended for production code
    });

    const dynamodb_GSI_name = 'ddb_sh_index'

    dynamoTable.addGlobalSecondaryIndex({
      indexName: dynamodb_GSI_name,
      partitionKey: { 
        name: 'ResourceId', 
        type: AttributeType.STRING 
      },
      sortKey: {
        name: 'Types',
        type: AttributeType.STRING
      },
    });

    // Custom Security Hub Lambda Function Resources 
    const lambdaCreateSHFindingRole = new iam.Role(this, 'lambdaCreateSHFindingRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "CustomSHFindingAutomationRole",
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaCustomSHLogExecutionPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
      ]
    });

    const CreateCustomSHFindingFunction = new Function(this, 'CreateCustomSHFindingFunction', {
      functionName: "Create_Custom_SH_Finding",
      runtime: Runtime.PYTHON_3_8,
      code: Code.fromAsset(join(__dirname, "../lambdas/create_sh_finding/")),
      handler: 'create_sh_finding.lambda_handler',
      description: 'Create AWS Security Hub finding from DynamoDB match.',
      timeout: cdk.Duration.seconds(300),
      role: lambdaCreateSHFindingRole,
      reservedConcurrentExecutions: 100,
      environment: {
        DYNAMODB_TABLE: dynamoTable.tableName,
        DYNAMODB_GSI: dynamodb_GSI_name
      },
    });

    const lambdaCreateSHFindingPolicyDoc = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "CreateSHFinding",
          effect: iam.Effect.ALLOW,
          actions: [
            "securityhub:BatchImportFindings"
          ],
          resources: [
            '*'
          ]   
        }),
      ],
    });

    const lambdaCreateSHFindingManagedPolicy = new iam.ManagedPolicy(this, 'lambdaCreateSHFindingManagedPolicy', {
      description: '',
      document:lambdaCreateSHFindingPolicyDoc,
      managedPolicyName: 'lambdaCreateSHFindingManagedPolicy',
      roles: [lambdaCreateSHFindingRole]
    });

    const CreateCustomSHFindingFunction_target = new LambdaFunction(CreateCustomSHFindingFunction)

    dynamoTable.grantReadWriteData(CreateCustomSHFindingFunction);
    
    // DynamoDB Lambda Function Resources
    const lambdaCreateDDBEntry = new iam.Role(this, 'lambdaCreateDDBEntry', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      roleName: "Dynamo_SH_Entry",
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this, 'lambdaSHExecutionPolicy', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
      ]
    });
    
    const CreateDynamoDBSHEntry = new Function(this, 'CreateDDBSHentry', {
      functionName: "Create_DDB_SH_Entry",
      runtime: Runtime.PYTHON_3_8,
      code: Code.fromAsset(join(__dirname, "../lambdas/create_ddb_sh_entry/")),
      handler: 'create_ddb_sh_entry.lambda_handler',
      description: 'Create Security Hub Findings entry in DynamoDB.',
      timeout: cdk.Duration.seconds(300),
      role: lambdaCreateDDBEntry,
      reservedConcurrentExecutions: 100,
      environment: {
        DYNAMODB_TABLE: dynamoTable.tableName,
        // DynamoDB Entry Time to Live (TTL) in days
        DYNAMODB_TTL: '30'
      },
    });
    
    const lambdaCreateDDBEntryPolicyDoc = new iam.PolicyDocument({
      statements: [
        new iam.PolicyStatement({
          sid: "DynamoDBTableAccess",
          effect: iam.Effect.ALLOW,
          actions: [
            "dynamodb:BatchGetItem",
            "dynamodb:BatchWriteItem",
            "dynamodb:ConditionCheckItem",
            "dynamodb:PutItem",
            "dynamodb:DescribeTable",
            "dynamodb:DeleteItem",
            "dynamodb:GetItem",
            "dynamodb:Scan",
            "dynamodb:Query",
            "dynamodb:UpdateItem"
          ],
          resources: [
            dynamoTable.tableArn
          ]   
        }),
        new iam.PolicyStatement({
          sid: "DynamoDBKMSKeyUse",
          effect: iam.Effect.ALLOW,
          actions: [
            "kms:Encrypt",
            "kms:GenerateDataKey*",
            "kms:DescribeKey",
            "kms:Decrypt"
          ],
          resources: [
            DynamoDBencryptionKey.keyArn
          ]   
        }),
      ],
    });

    const lambdaCreateDDBEntryManagedPolicy = new iam.ManagedPolicy(this, 'lambdaCreateDDBEntryManagedPolicy', {
      description: '',
      document:lambdaCreateDDBEntryPolicyDoc,
      managedPolicyName: 'lambdaAddDDBManagedPolicy',
      roles: [lambdaCreateDDBEntry]
    });

    const CreateDynamoDBSHEntry_target = new LambdaFunction(CreateDynamoDBSHEntry)

    // DynamoDB Event Stream for new DynamoDB entries to check Security Hub Correlation
    CreateCustomSHFindingFunction.addEventSource(new DynamoEventSource(dynamoTable, {
      startingPosition: StartingPosition.LATEST,
    }));

    // CloudWatch EventBridge rule for GuardDuty findings to DynamoDB
    const RespondSecurityHubEvent_GuardDuty = new Rule(this, 'RespondSecurityHubEvent_GuardDuty', {
      description: 'Creates a DynamoDB entry for specific GuardDuty Finding being generated.',
      enabled: true,
      eventPattern: {
        "source": [
          "aws.securityhub"
        ],
        "detailType": [
          "Security Hub Findings - Imported"
        ],
        "detail": {
          "findings": {
            "ProductName":[
              "GuardDuty"
            ],
            "Types":[
              { "prefix": "TTPs/Exfiltration:S3-"},
              { "prefix": "Unusual Behaviors/VM/Behavior:EC2-NetworkPortUnusual"},
              { "prefix": "TTPs/Command and Control/Backdoor:EC2-"},
              { "prefix": "TTPs/Initial Access/UnauthorizedAccess:EC2-SSHBruteForce"},
              { "prefix": "TTPs/Initial Access/UnauthorizedAccess:EC2-RDPBruteForce"},
            ],
            "Workflow": {
              "Status": [
                "NEW"
              ]
            },
            "RecordState": [
              "ACTIVE"
            ],
          }
        }
      },
      ruleName: 'Create_Dynamo_Entry_from_Security_Hub_GuardDuty',
      targets: [CreateDynamoDBSHEntry_target]
    }
    );
    // CloudWatch EventBridge rule for Security Hub findings to DynamoDB
    const RespondSecurityHubEvent_SecurityHub = new Rule(this, 'RespondSecurityHubEvent_SecurityHub', {
      description: 'Creates a DynamoDB entry for specific Security Hub Finding being generated.',
      enabled: true,
      eventPattern: {
        "source": [
          "aws.securityhub"
        ],
        "detailType": [
          "Security Hub Findings - Imported"
        ],
        "detail": {
          "findings": {
            "ProductName":[
              "Security Hub"
            ],
            //"Title":[
            //  { "prefix": "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports"},
            //  { "prefix": "EC2.9"}
            //],
            "ProductFields": {
              "ControlId": [
                "EC2.18",
                "EC2.9"
              ]
            },
            "Workflow": {
              "Status": [
                "NEW"
              ]
            },
            "RecordState": [
              "ACTIVE"
            ],
          }
        }
      },
      ruleName: 'Create_Dynamo_Entry_Security_Hub',
      targets: [CreateDynamoDBSHEntry_target]
    }
    );
    // CloudWatch EventBridge rule for Macie findings to DynamoDB
    const RespondSecurityHubEvent_Macie = new Rule(this, 'RespondSecurityHubEvent_Macie', {
      description: 'Creates a DynamoDB entry for specific Macie Finding being generated.',
      enabled: true,
      eventPattern: {
        "source": [
          "aws.securityhub"
        ],
        "detailType": [
          "Security Hub Findings - Imported"
        ],
        "detail": {
          "findings": {
            "ProductName":[
              "Macie"
            ],
            "Types":[
              { "prefix": "Sensitive Data Identifications/PII/SensitiveData:"}
            ],
            "WorkflowState": [
              "NEW"
            ],
            "RecordState": [
              "ACTIVE"
            ],
          }
        }
      },
      ruleName: 'Create_Dynamo_Entry_from_Security_Hub_Macie',
      targets: [CreateDynamoDBSHEntry_target]
    }
    );
    // CloudWatch EventBridge rule for Inspector findings to DynamoDB
    const RespondSecurityHubEvent_Inspector = new Rule(this, 'RespondSecurityHubEvent_Inspector', {
      description: 'Creates a DynamoDB entry for specific Inspector Finding being generated.',
      enabled: true,
      eventPattern: {
        "source": [
          "aws.securityhub"
        ],
        "detailType": [
          "Security Hub Findings - Imported"
        ],
        "detail": {
          "findings": {
            "ProductName":[
              "Inspector"
            ],
            "Severity": {
              "Label": ["CRITICAL"]
            },
            "WorkflowState": [
              "NEW"
            ],
            "RecordState": [
              "ACTIVE"
            ],
          }
        }
      },
      ruleName: 'Create_Dynamo_Entry_from_Security_Hub_Inspector',
      targets: [CreateDynamoDBSHEntry_target]
    }
    );

  }
}

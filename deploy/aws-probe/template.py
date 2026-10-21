"""Generate a CloudFormation template; does not contact AWS."""

import json
from pathlib import Path


def ref(name):
    return {"Ref": name}


def arn(name):
    return {"Fn::GetAtt": [name, "Arn"]}


def sub(value):
    return {"Fn::Sub": value}


def policy(statements):
    return {"Version": "2012-10-17", "Statement": statements}


def allow(actions, resource):
    return {"Effect": "Allow", "Action": actions, "Resource": resource}


def template():
    resources = {
        "Receipts": {
            "Type": "AWS::DynamoDB::Table",
            "Properties": {
                "AttributeDefinitions": [{"AttributeName": "job_id", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "job_id", "KeyType": "HASH"}],
                "BillingMode": "PROVISIONED",
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
                "SSESpecification": {"SSEEnabled": True},
            },
        },
        "Failures": {
            "Type": "AWS::SQS::Queue",
            "Properties": {"SqsManagedSseEnabled": True, "MessageRetentionPeriod": 1209600},
        },
        "ScheduleGroup": {"Type": "AWS::Scheduler::ScheduleGroup"},
        "Logs": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {
                "LogGroupName": sub("/aws/lambda/${AWS::StackName}-receipt"),
                "RetentionInDays": 7,
            },
        },
        "FunctionRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": policy([{
                    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }]),
                "Policies": [{"PolicyName": "WriteDummyReceipt", "PolicyDocument": policy([
                    allow(["dynamodb:PutItem", "dynamodb:GetItem"], arn("Receipts")),
                    allow(["logs:CreateLogStream", "logs:PutLogEvents"], arn("Logs")),
                    allow("sqs:SendMessage", arn("Failures")),
                ])}],
            },
        },
        "Function": {
            "Type": "AWS::Lambda::Function",
            "DependsOn": "Logs",
            "Properties": {
                "FunctionName": sub("${AWS::StackName}-receipt"),
                "Description": "Dummy scheduling probe; no LINE client or session",
                "Runtime": "python3.12", "Handler": "index.handler",
                "Architectures": ["arm64"], "MemorySize": 128, "Timeout": 15,
                "Role": arn("FunctionRole"),
                "Environment": {"Variables": {"RECEIPTS_TABLE": ref("Receipts")}},
                "Code": {"ZipFile": Path(__file__).with_name("handler.py").read_text()},
            },
        },
        "AsyncDelivery": {
            "Type": "AWS::Lambda::EventInvokeConfig",
            "Properties": {
                "FunctionName": ref("Function"), "Qualifier": "$LATEST",
                "MaximumEventAgeInSeconds": 900, "MaximumRetryAttempts": 2,
                "DestinationConfig": {"OnFailure": {"Destination": arn("Failures")}},
            },
        },
        "SchedulerRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": policy([{
                    "Effect": "Allow", "Principal": {"Service": "scheduler.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": ref("AWS::AccountId")},
                        "ArnEquals": {"aws:SourceArn": arn("ScheduleGroup")},
                    },
                }]),
                "Policies": [{"PolicyName": "InvokeDummyReceipt", "PolicyDocument": policy([
                    allow("lambda:InvokeFunction", arn("Function")),
                    allow("sqs:SendMessage", arn("Failures")),
                ])}],
            },
        },
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Disposable synthetic scheduling probe. Contains no LINE integration.",
        "Resources": resources,
        "Outputs": {key: {"Value": value} for key, value in {
            "FunctionArn": arn("Function"), "RoleArn": arn("SchedulerRole"),
            "TableName": ref("Receipts"), "GroupName": ref("ScheduleGroup"),
            "FailureArn": arn("Failures"), "FailureQueueUrl": ref("Failures"),
        }.items()},
    }


if __name__ == "__main__":
    print(json.dumps(template(), indent=2))

"""Reproducible AWS resources for the private personal scheduler."""
def ref(n): return {"Ref":n}
def arn(n): return {"Fn::GetAtt":[n,"Arn"]}
def sub(s): return {"Fn::Sub":s}
def policy(statements): return {"Version":"2012-10-17","Statement":statements}
def allow(actions,resource,condition=None):
    s={"Effect":"Allow","Action":actions,"Resource":resource}
    if condition:s["Condition"]=condition
    return s
def trust(service):
    return policy([{"Effect":"Allow","Principal":{"Service":service},"Action":"sts:AssumeRole"}])
def table():
    return {"Type":"AWS::DynamoDB::Table","DeletionPolicy":"Retain","UpdateReplacePolicy":"Retain",
      "Properties":{"AttributeDefinitions":[{"AttributeName":"id","AttributeType":"S"}],
      "KeySchema":[{"AttributeName":"id","KeyType":"HASH"}],"BillingMode":"PROVISIONED",
      "ProvisionedThroughput":{"ReadCapacityUnits":2,"WriteCapacityUnits":2},
      "SSESpecification":{"SSEEnabled":True}}}
def template():
    r={"Jobs":table(),"Sessions":table(),
       "Group":{"Type":"AWS::Scheduler::ScheduleGroup"},
       "Failures":{"Type":"AWS::SQS::Queue","Properties":{"SqsManagedSseEnabled":True,"MessageRetentionPeriod":1209600}}}
    r["Jobs"]["Properties"]["TimeToLiveSpecification"]={"AttributeName":"expires_at","Enabled":True}
    r["Files"]={"Type":"AWS::S3::Bucket","DeletionPolicy":"Retain","UpdateReplacePolicy":"Retain","Properties":{
        "PublicAccessBlockConfiguration":{"BlockPublicAcls":True,"IgnorePublicAcls":True,"BlockPublicPolicy":True,"RestrictPublicBuckets":True},
        "OwnershipControls":{"Rules":[{"ObjectOwnership":"BucketOwnerEnforced"}]},
        "VersioningConfiguration":{"Status":"Enabled"},
        "BucketEncryption":{"ServerSideEncryptionConfiguration":[{"ServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]},
        "CorsConfiguration":{"CorsRules":[{"AllowedOrigins":[ref("SiteOrigin")],"AllowedMethods":["POST"],"AllowedHeaders":["*"],"MaxAge":300}]},
        "LifecycleConfiguration":{"Rules":[
            {"Id":"AbandonedUploads","Status":"Enabled","TagFilters":[{"Key":"state","Value":"staging"}],"ExpirationInDays":1,"NoncurrentVersionExpiration":{"NoncurrentDays":1}},
            {"Id":"StorageCeiling","Status":"Enabled","Prefix":"uploads/","ExpirationInDays":370,"NoncurrentVersionExpiration":{"NoncurrentDays":370},"AbortIncompleteMultipartUpload":{"DaysAfterInitiation":1}}
        ]}}}
    r["FilesPolicy"]={"Type":"AWS::S3::BucketPolicy","Properties":{"Bucket":ref("Files"),"PolicyDocument":policy([
        {"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":[arn("Files"),sub("${Files.Arn}/*")],
         "Condition":{"Bool":{"aws:SecureTransport":"false"}}}
    ])}}
    for name in ["Worker","API"]:
        r[name+"Logs"]={"Type":"AWS::Logs::LogGroup","Properties":{
            "LogGroupName":sub("/aws/lambda/${AWS::StackName}-"+name.lower()),"RetentionInDays":7}}
    r["WorkerRole"]={"Type":"AWS::IAM::Role","Properties":{
        "AssumeRolePolicyDocument":trust("lambda.amazonaws.com"),
        "Policies":[{"PolicyName":"SessionAndDelivery","PolicyDocument":policy([
            allow(["dynamodb:GetItem","dynamodb:PutItem","dynamodb:UpdateItem","dynamodb:DeleteItem","dynamodb:ConditionCheckItem"],[arn("Jobs"),arn("Sessions")]),
            allow(["logs:CreateLogStream","logs:PutLogEvents"],arn("WorkerLogs")),
            allow("sqs:SendMessage",arn("Failures"))
            ,allow(["s3:GetObjectVersion","s3:DeleteObjectVersion"],sub("${Files.Arn}/uploads/*"))
        ])}]}}
    r["SchedulerRole"]={"Type":"AWS::IAM::Role","Properties":{
        "AssumeRolePolicyDocument":policy([{"Effect":"Allow","Principal":{"Service":"scheduler.amazonaws.com"},
            "Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":ref("AWS::AccountId")},
            "ArnEquals":{"aws:SourceArn":arn("Group")}}}]),
        "Policies":[{"PolicyName":"DispatchOnly","PolicyDocument":policy([
            allow("lambda:InvokeFunction",arn("Worker")),allow("sqs:SendMessage",arn("Failures"))])}]}}
    r["APIRole"]={"Type":"AWS::IAM::Role","Properties":{
        "AssumeRolePolicyDocument":trust("lambda.amazonaws.com"),
        "Policies":[{"PolicyName":"SchedulingOnly","PolicyDocument":policy([
            allow(["dynamodb:GetItem","dynamodb:PutItem","dynamodb:UpdateItem","dynamodb:Scan"],arn("Jobs")),
            allow(["scheduler:CreateSchedule","scheduler:DeleteSchedule"],
                  sub("arn:${AWS::Partition}:scheduler:${AWS::Region}:${AWS::AccountId}:schedule/${Group}/*")),
            allow("iam:PassRole",arn("SchedulerRole"),{"StringEquals":{"iam:PassedToService":"scheduler.amazonaws.com"}}),
            allow("lambda:InvokeFunction",arn("Worker")),
            allow(["logs:CreateLogStream","logs:PutLogEvents"],arn("APILogs"))
            ,allow(["s3:PutObject","s3:PutObjectTagging","s3:PutObjectVersionTagging","s3:GetObject","s3:DeleteObjectVersion"],sub("${Files.Arn}/uploads/*"))
        ])}]}}
    for name in ["Worker","API"]:
        env={"JOBS_TABLE":ref("Jobs"),"FILES_BUCKET":ref("Files")}
        if name=="Worker":env.update({"SESSION_TABLE":ref("Sessions"),"SESSION_KEY":ref("SessionKey")})
        else:env.update({"BRIDGE_TOKEN":ref("BridgeToken"),"WORKER_NAME":ref("Worker"),
            "WORKER_ARN":arn("Worker"),"SCHEDULE_GROUP":ref("Group"),
            "SCHEDULER_ROLE":arn("SchedulerRole"),"FAILURE_ARN":arn("Failures")})
        r[name]={"Type":"AWS::Lambda::Function","DependsOn":name+"Logs","Properties":{
            "FunctionName":sub("${AWS::StackName}-"+name.lower()),"Runtime":"python3.12",
            "Handler":"handler."+("worker" if name=="Worker" else "controller"),
            "Architectures":["arm64"],"Timeout":120 if name=="Worker" else 25,
            "MemorySize":512 if name=="Worker" else 128,"Role":arn(name+"Role"),
            "Code":{"S3Bucket":ref("ArtifactBucket"),"S3Key":ref("ArtifactKey")},
            "Environment":{"Variables":env}}}
    r["AsyncDelivery"]={"Type":"AWS::Lambda::EventInvokeConfig","Properties":{
        "FunctionName":ref("Worker"),"Qualifier":"$LATEST","MaximumEventAgeInSeconds":900,
        "MaximumRetryAttempts":2,"DestinationConfig":{"OnFailure":{"Destination":arn("Failures")}}}}
    r["URL"]={"Type":"AWS::Lambda::Url","Properties":{"TargetFunctionArn":arn("API"),"AuthType":"NONE"}}
    r["URLPermission"]={"Type":"AWS::Lambda::Permission","Properties":{
        "FunctionName":ref("API"),"Action":"lambda:InvokeFunctionUrl","Principal":"*","FunctionUrlAuthType":"NONE"}}
    r["URLInvokePermission"]={"Type":"AWS::Lambda::Permission","Properties":{
        "FunctionName":ref("API"),"Action":"lambda:InvokeFunction","Principal":"*","InvokedViaFunctionUrl":True}}
    return {"AWSTemplateFormatVersion":"2010-09-09","Description":"Private LINE scheduler with encrypted session and fenced single-attempt sends.",
      "Parameters":{"ArtifactBucket":{"Type":"String"},"ArtifactKey":{"Type":"String"},
        "SiteOrigin":{"Type":"String","AllowedPattern":"https://[A-Za-z0-9.-]+","Description":"Exact private Site origin for attachment uploads; no trailing slash"},
        "SessionKey":{"Type":"String","NoEcho":True},"BridgeToken":{"Type":"String","NoEcho":True}},
      "Resources":r,"Outputs":{k:{"Value":v} for k,v in {
        "APIURL":{"Fn::GetAtt":["URL","FunctionUrl"]},"APIName":ref("API"),"WorkerName":ref("Worker"),
        "JobsTable":ref("Jobs"),"SessionTable":ref("Sessions"),"FilesBucket":ref("Files"),"GroupName":ref("Group"),"Failures":ref("Failures")}.items()}}

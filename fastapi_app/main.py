from fastapi import FastAPI, HTTPException
from models import AWSCredentials, ECSClusterModel, VPCModel, LambdaModel, S3UploadModel, S3BucketModel, CognitoGroupModel
from cryptography.fernet import Fernet
import boto3
import json

app = FastAPI()

# Encryption key for credentials
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Endpoint to store AWS credentials securely
@app.post("/store_credentials")
def store_credentials(credentials: AWSCredentials):
    encrypted_access_key = cipher_suite.encrypt(credentials.AWS_ACCESS_KEY.encode())
    encrypted_secret_key = cipher_suite.encrypt(credentials.AWS_SECRET_KEY.encode())
    with open('aws_credentials.json', 'w') as f:
        json.dump({
            'AWS_ACCESS_KEY': encrypted_access_key.decode(),
            'AWS_SECRET_KEY': encrypted_secret_key.decode()
        }, f)
    return {"message": "Credentials stored securely"}

# Function to load and decrypt AWS credentials
def load_credentials():
    with open('aws_credentials.json', 'r') as f:
        data = json.load(f)
    encrypted_access_key = data['AWS_ACCESS_KEY']
    encrypted_secret_key = data['AWS_SECRET_KEY']
    aws_access_key = cipher_suite.decrypt(encrypted_access_key.encode()).decode()
    aws_secret_key = cipher_suite.decrypt(encrypted_secret_key.encode()).decode()
    return aws_access_key, aws_secret_key

# Initialize boto3 clients
def initialize_clients():
    aws_access_key, aws_secret_key = load_credentials()
    ecs_client = boto3.client('ecs', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
    ec2_client = boto3.client('ec2', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
    lambda_client = boto3.client('lambda', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
    s3_client = boto3.client('s3', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
    cognito_client = boto3.client('cognito-idp', aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key)
    return ecs_client, ec2_client, lambda_client, s3_client, cognito_client

# Endpoint to create ECS cluster
@app.post("/create_ecs_cluster")
def create_ecs_cluster(cluster: ECSClusterModel):
    ecs_client, _, _, _, _ = initialize_clients()
    response = ecs_client.create_cluster(clusterName=cluster.cluster_name)
    return response

# Endpoint to create VPC
@app.post("/create_vpc")
def create_vpc(vpc: VPCModel):
    _, ec2_client, _, _, _ = initialize_clients()
    response = ec2_client.create_vpc(CidrBlock=vpc.cidr_block)
    return response

# Endpoint to create Lambda function from Dockerized container
@app.post("/create_lambda_function")
def create_lambda_function(lambda_function: LambdaModel):
    _, _, lambda_client, _, _ = initialize_clients()
    response = lambda_client.create_function(
        FunctionName=lambda_function.function_name,
        Code={'ImageUri': lambda_function.image_uri},
        Role=lambda_function.role_arn,
        PackageType='Image'
    )
    return response

# Endpoint to upload file to S3
@app.post("/upload_file_to_s3")
def upload_file_to_s3(upload: S3UploadModel):
    _, _, _, s3_client, _ = initialize_clients()
    response = s3_client.upload_file(upload.file_name, upload.bucket_name, upload.object_name or upload.file_name)
    return {"message": "File uploaded successfully"}

# Endpoint to create S3 bucket
@app.post("/create_s3_bucket")
def create_s3_bucket(bucket: S3BucketModel):
    _, _, _, s3_client, _ = initialize_clients()
    response = s3_client.create_bucket(Bucket=bucket.bucket_name)
    return response

# Endpoint to create Cognito group
@app.post("/create_cognito_group")
def create_cognito_group(group: CognitoGroupModel):
    _, _, _, _, cognito_client = initialize_clients()
    response = cognito_client.create_group(
        UserPoolId=group.user_pool_id,
        GroupName=group.group_name
    )
    return response

from pydantic import BaseModel, Field
from typing import Optional

class AWSCredentials(BaseModel):
    AWS_ACCESS_KEY: str = Field(..., min_length=16, max_length=128)
    AWS_SECRET_KEY: str = Field(..., min_length=16, max_length=128)

class ECSClusterModel(BaseModel):
    cluster_name: str = Field(..., min_length=1, max_length=255)

class VPCModel(BaseModel):
    cidr_block: str = Field(..., pattern=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')

class LambdaModel(BaseModel):
    function_name: str = Field(..., min_length=1, max_length=255)
    image_uri: str = Field(..., min_length=1, max_length=255)
    role_arn: str = Field(..., min_length=20, max_length=2048)

class S3UploadModel(BaseModel):
    bucket_name: str = Field(..., min_length=3, max_length=63)
    file_name: str = Field(..., min_length=1, max_length=1024)
    object_name: Optional[str] = None

class S3BucketModel(BaseModel):
    bucket_name: str = Field(..., min_length=3, max_length=63)

class CognitoGroupModel(BaseModel):
    user_pool_id: str = Field(..., min_length=1, max_length=55)
    group_name: str = Field(..., min_length=1, max_length=128)

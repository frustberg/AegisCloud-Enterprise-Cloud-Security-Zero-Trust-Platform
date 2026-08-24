import boto3

s3 = boto3.client("s3")

def lambda_handler(event, context):

    bucket = "aegiscloud-test-bucket"

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            'BlockPublicAcls': True,
            'IgnorePublicAcls': True,
            'BlockPublicPolicy': True,
            'RestrictPublicBuckets': True
        }
    )

    return {
        "status": "remediated"
    }
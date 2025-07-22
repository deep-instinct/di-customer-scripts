# Instructions for use
# install python with the following dependencies - boto3, pandas and openpyxl
# install AWS CLI
# run "aws configure" to setup the access to the S3 buckets.  Ensure your IAM role has the following permissions s3:ListAllMyBuckets, s3:ListBucket, s3:GetObjectTagging
# run the python script "python DSX-C S3 malicious files.py"

import boto3
import pandas as pd
from botocore.exceptions import ClientError

# Create S3 client
s3 = boto3.client('s3')

malicious_files = []

# List all S3 buckets
buckets = s3.list_buckets()['Buckets']

for bucket in buckets:
    bucket_name = bucket['Name']
    print(f"Checking bucket: {bucket_name}")

    paginator = s3.get_paginator('list_objects_v2')
    for page in paginator.paginate(Bucket=bucket_name):
        if 'Contents' not in page:
            continue
        for obj in page['Contents']:
            key = obj['Key']
            try:
                response = s3.get_object_tagging(Bucket=bucket_name, Key=key)
                tags = {tag['Key']: tag['Value'] for tag in response['TagSet']}
                verdict = tags.get('dps-verdict', '')
                if verdict.startswith('MALICIOUS'):
                    malicious_files.append({
                        'Bucket': bucket_name,
                        'Directory': key,
                        'Size (Bytes)': obj['Size'],
                        'dps-verdict': verdict
                    })
            except ClientError as e:
                print(f"Error accessing tags for {bucket_name}/{key}: {e.response['Error']['Message']}")

# Export to Excel
if malicious_files:
    df = pd.DataFrame(malicious_files)
    df.to_excel('malicious_files.xlsx', index=False)
    print("MALICIOUS-tagged files exported to 'malicious_files.xlsx'.")
else:
    print("No files with dps-verdict=MALICIOUS* found.")


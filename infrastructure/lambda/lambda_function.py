import os
import re
import json
import boto3
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

# Initialize AWS Service Clients
s3_client = boto3.client('s3')
bedrock_client = boto3.client('bedrock-runtime')

# Read environment variables injected by AWS Lambda configuration
OPENSEARCH_ENDPOINT = os.environ.get('OPENSEARCH_ENDPOINT')  # e.g., ://amazonaws.com
INDEX_NAME = os.environ.get('OPENSEARCH_INDEX', 'fraud-forensics-vector-db')
AWS_REGION = os.environ.get('AWS_REGION', 'ap-south-1')

def mask_pii(text: str) -> str:
    """
    Forensic-grade regex masking to sanitize raw logs before they reach the vector database.
    Redacts Primary Account Numbers (Credit Cards) and US Social Security Numbers.
    """
    # Mask Credit Cards (13 to 16 digits structural matches)
    cc_pattern = r'\b(?:\d[ -]*?){13,16}\b'
    text = re.sub(cc_pattern, "[REDACTED_CREDIT_CARD]", text)
    
    # Mask Social Security Numbers / National IDs (xxx-xx-xxxx format)
    ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
    text = re.sub(ssn_pattern, "[REDACTED_NATIONAL_ID]", text)
    
    return text

def get_vector_embeddings(text: str) -> list:
    """
    Invokes Amazon Bedrock Titan Text Embeddings V2 model to translate 
    masked text strings into numerical high-dimensional vector arrays.
    """
    model_id = "amazon.titan-embed-text-v2:0"
    body = json.dumps({
        "inputText": text,
        "dimensions": 1024,  # Standard dimensional density for semantic lookups
        "normalize": True
    })
    
    response = bedrock_client.invoke_model(
        body=body,
        modelId=model_id,
        accept="application/json",
        contentType="application/json"
    )
    
    response_body = json.loads(response.get('body').read())
    return response_body.get('embedding')

def get_opensearch_client():
    """
    Builds a secure, stateless OpenSearch Client using AWS SigV4 request signing
    specifically designated for Serverless OpenSearch collections ('aoss').
    """
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(
        credentials.access_key,
        credentials.secret_key,
        AWS_REGION,
        'aoss',  # Crucial: Must be 'aoss' for Serverless, not 'es'
        session_token=credentials.token
    )
    
    # Clean the endpoint prefix if present
    host = OPENSEARCH_ENDPOINT.replace("https://", "").replace("http://", "")
    
    return OpenSearch(
        hosts=[{'host': host, 'port': 443}],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )

def lambda_handler(event, context):
    """
    Main execution entry point triggered natively by AWS S3 ObjectCreated events.
    """
    print(f"Received native S3 Event: {json.dumps(event)}")
    
    try:
        # 1. Parse S3 bucket name and file path from the incoming event record
        bucket_name = event['Records'][0]['s3']['bucket']['name']
        s3_key = event['Records'][0]['s3']['object']['key']
        
        print(f"Processing object: {s3_key} from bucket: {bucket_name}")
        
        # 2. Extract the raw log payload from the S3 bucket object
        s3_object = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
        raw_log_content = s3_object['Body'].read().decode('utf-8')
        
        # 3. Apply forensic PII masking rules
        masked_content = mask_pii(raw_log_content)
        
        # 4. Generate AI semantic embeddings via AWS Bedrock
        vector_array = get_vector_embeddings(masked_content)
        
        # 5. Extract operational metadata from pathing (assuming format: caseId/file.txt)
        case_id = s3_key.split('/')[0] if '/' in s3_key else "unassigned-case"
        
        # 6. Compose the target search document
        document = {
            "caseId": case_id,
            "s3Key": s3_key,
            "content": masked_content,
            "log_vector": vector_array  # The OpenSearch index mapping must match this field name
        }
        
        # 7. Establish signed cloud connection and index the data
        client = get_opensearch_client()
        response = client.index(
            index=INDEX_NAME,
            body=document,
            id=s3_key  # Uses the S3 storage path as unique document ID to prevent duplicate indexing
        )
        
        print(f"Successfully vectorized and indexed document. OpenSearch status: {response.get('result')}")
        return {"status": "SUCCESS", "indexed_id": s3_key}
        
    except Exception as e:
        print(f"Fatal operational exception encountered in processing pipeline: {str(e)}")
        raise e

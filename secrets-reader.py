import boto3
import botocore
import os

def load_credentials(file_path="creds.txt"):
    """Load IAM user credentials and optional role ARN from a file."""
    creds = {}
    try:
        with open(file_path, "r") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    creds[key.strip()] = value.strip()
    except FileNotFoundError:
        print(f"Credential file '{file_path}' not found!")
        exit(1)
    return creds

def init_base_session(creds):
    """Initialize a session with static IAM credentials (used only for STS)."""
    return boto3.session.Session(
        aws_access_key_id=creds["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=creds["AWS_SECRET_ACCESS_KEY"],
        region_name=creds.get("AWS_REGION", "us-east-1")
    )

def assume_role(base_session, role_arn, region):
    """Use STS to assume a role and return a session with temporary credentials."""
    sts_client = base_session.client("sts", region_name=region)
    try:
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="SecretsReaderSession"
        )
        temp_creds = response["Credentials"]
        print("Role assumed successfully. Temporary credentials obtained.\n")

        # Create a session with temporary credentials
        return boto3.session.Session(
            aws_access_key_id=temp_creds["AccessKeyId"],
            aws_secret_access_key=temp_creds["SecretAccessKey"],
            aws_session_token=temp_creds["SessionToken"],
            region_name=region
        )
    except botocore.exceptions.ClientError as e:
        print("Failed to assume role:", e)
        return base_session  # fallback to base session if role assumption fails

def list_secrets(client):
    """List all secrets available to the current session."""
    try:
        print("\nAvailable Secrets:\n")
        secrets = []
        paginator = client.get_paginator("list_secrets")
        index = 1
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                print(f"{index}. {secret['Name']}")
                secrets.append(secret["Name"])
                index += 1
        if not secrets:
            print("No secrets found.")
        return secrets
    except botocore.exceptions.ClientError as e:
        print("Error listing secrets:", e)
        return []

def get_secret(client, secret_name):
    """Retrieve the secret value from Secrets Manager using temporary credentials."""
    try:
        response = client.get_secret_value(SecretId=secret_name)
        print("\nSecret Retrieved Successfully!\n")
        print("Secret Name:", secret_name)
        if "SecretString" in response:
            print("Secret Value:", response["SecretString"])
        else:
            print("Binary Secret (Base64):", response["SecretBinary"])
    except botocore.exceptions.ClientError as e:
        print("Error retrieving secret:", e)
        if e.response['Error']['Code'] == "AccessDeniedException":
            print("Check that your role has permissions for Secrets Manager and KMS decryption.")

def main():
    creds = load_credentials("creds.txt")
    base_session = init_base_session(creds)

    # Use STS assume-role if a role ARN is provided
    if "ASSUME_ROLE_ARN" in creds and creds["ASSUME_ROLE_ARN"]:
        session = assume_role(base_session, creds["ASSUME_ROLE_ARN"], creds.get("AWS_REGION", "us-east-1"))
    else:
        session = base_session

    client = session.client("secretsmanager")
    secrets = list_secrets(client)
    if not secrets:
        return

    choice = input("\nEnter secret name (or number) to retrieve: ").strip()
    if choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(secrets):
            secret_name = secrets[idx]
        else:
            print("Invalid selection.")
            return
    else:
        secret_name = choice

    get_secret(client, secret_name)

if __name__ == "__main__":
    main()

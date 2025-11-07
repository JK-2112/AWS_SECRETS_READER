import boto3
import hmac
import hashlib
import base64
import getpass
import botocore.exceptions

# -------------------------------
# CONFIGURATION
# -------------------------------
REGION = "YOUR AWS REGION"
USER_POOL_ID = "YOUR USER POOL ID"
CLIENT_ID = "YOUR CLIENT ID"
CLIENT_SECRET = "YOUR CLIENT SECRET"  
IDENTITY_POOL_ID = "YOUR IDENTITY POOL ID"
# -------------------------------


def get_secret_hash(username: str) -> str:
    message = username + CLIENT_ID
    dig = hmac.new(
        CLIENT_SECRET.encode("utf-8"),
        msg=message.encode("utf-8"),
        digestmod=hashlib.sha256
    ).digest()
    return base64.b64encode(dig).decode()


def authenticate_user(username: str, password: str) -> dict:
    client = boto3.client("cognito-idp", region_name=REGION)
    print("🔐 Authenticating user with Cognito...")
    try:
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                "SECRET_HASH": get_secret_hash(username)
            }
        )
        print("✅ Authenticated Successfully!")
        return response["AuthenticationResult"]

    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]

        if code == "NotAuthorizedException":
            print("🚫 Authentication failed: Incorrect username or password.")
        elif code == "UserNotFoundException":
            print("🚫 Authentication failed: User does not exist in this user pool.")
        else:
            print(f"🚫 Authentication error: {msg}")
        exit(1)


def get_temporary_credentials(id_token: str) -> dict:
    print("\n🔄 Getting temporary AWS credentials via Cognito Identity...")
    client = boto3.client("cognito-identity", region_name=REGION)

    try:
        identity_id_response = client.get_id(
            IdentityPoolId=IDENTITY_POOL_ID,
            Logins={f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}": id_token}
        )
        identity_id = identity_id_response["IdentityId"]

        credentials = client.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}": id_token}
        )["Credentials"]

        print("✅ Temporary AWS Credentials Retrieved")
        return credentials

    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        msg = e.response["Error"]["Message"]

        print("\n🚫 Failed to get temporary credentials.")
        if "ambiguous role mapping" in msg.lower():
            print("❗ Cognito cannot determine which IAM role to assign.")
            print("👉 Check your Identity Pool's 'Role selection' and 'Role resolution' settings.")
            print("   - Ensure it's set to 'Choose role with preferred_role claim in tokens'.")
            print("👉 Also verify that the user belongs to a Cognito group with a role attached.")
        elif code == "NotAuthorizedException":
            print("🚫 Unauthorized: The token or role mapping may be invalid.")
        else:
            print(f"⚠️ AWS Error: {msg}")
        exit(1)


def access_secrets_interactively(creds: dict):
    secrets_client = boto3.client(
        "secretsmanager",
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretKey"],
        aws_session_token=creds["SessionToken"]
    )

    print("\n🔍 Fetching available secrets...")
    try:
        secrets = secrets_client.list_secrets()
        secret_list = secrets.get("SecretList", [])
        if not secret_list:
            print("ℹ️ No secrets found in your account.")
            return

        print("\n📜 Available Secrets:")
        for idx, secret in enumerate(secret_list, start=1):
            print(f"{idx}. {secret['Name']}")

        choice = input("\n👉 Enter the number of the secret you want to view: ").strip()
        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(secret_list):
            print("🚫 Invalid choice.")
            return

        selected_secret = secret_list[int(choice) - 1]["Name"]
        print(f"\n🔑 Attempting to read secret: {selected_secret}")

        try:
            secret_value = secrets_client.get_secret_value(SecretId=selected_secret)
            print("\n✅ Secret Retrieved Successfully!")
            print(f"🗝️ Secret Name: {selected_secret}")
            print(f"🔒 Secret Value: {secret_value.get('SecretString', '<binary or empty>')}")

        except botocore.exceptions.ClientError as e:
            code = e.response["Error"]["Code"]

            if code == "AccessDeniedException":
                print("🚫 Access Denied: You do not have permission to read this secret.")
            elif code == "ResourceNotFoundException":
                print("🚫 Secret not found. It may have been deleted or renamed.")
            elif code == "DecryptionFailure":
                print("🚫 KMS Decryption failed. Check KMS permissions or key policy.")
            else:
                print(f"⚠️ Unexpected AWS Error while reading secret: {code}")

        except Exception as e:
            print(f"🚫 Unexpected error while accessing secret: {e}")

    except botocore.exceptions.ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AccessDeniedException":
            print("🚫 Access Denied: You do not have permission to list secrets.")
        else:
            print(f"⚠️ Unexpected AWS Error while listing secrets: {code}")

    except Exception as e:
        print(f"🚫 Failed to list secrets: {e}")


def main():
    username = input("Enter username: ").strip()
    password = getpass.getpass("Enter password: ")

    tokens = authenticate_user(username, password)
    id_token = tokens["IdToken"]

    creds = get_temporary_credentials(id_token)

    sts = boto3.client(
        "sts",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretKey"],
        aws_session_token=creds["SessionToken"]
    )
    identity = sts.get_caller_identity()
    print(f"\n🔍 Currently assumed role ARN: {identity['Arn']}")

    access_secrets_interactively(creds)


if __name__ == "__main__":
    main()

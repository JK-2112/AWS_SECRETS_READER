# 🔐 Secure Access to AWS Secrets Manager using IAM & KMS

This project demonstrates **secure access control** to AWS **Secrets Manager** secrets that are protected by **KMS (Key Management Service)** encryption.

It uses an **IAM user or IAM role** with fine-grained permissions to list and retrieve secrets using the **AWS SDK for Python (boto3)**.

---

## 🧠 Overview

- **Goal:** Access AWS Secrets Manager secrets securely using IAM credentials.
- **Encryption:** The secrets are encrypted using a **KMS key** created in your AWS account.
- **Access Control:** Controlled via **IAM policies** (principle of least privilege).
- **Language:** Python (uses `boto3` and `botocore` libraries).
- **Input:** Credentials loaded from `creds.txt`.
- **Output:** Lists available secrets and retrieves the selected secret securely.

---

## 🧰 Prerequisites

Before running the script, ensure you have:

1. **AWS account** with a configured KMS key and Secrets Manager secret.
2. **IAM user or IAM role** with permissions for:
    - `secretsmanager:ListSecrets`
    - `secretsmanager:GetSecretValue`
    - `kms:Decrypt`
3. **Python 3.x** installed.
4. **boto3** and **botocore** libraries installed:
    
    ```bash
    pip install boto3 botocore
    
    ```
    

---

## ⚙️ Setup Instructions

### 1️⃣ Clone or Download this Repository

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

```

### 2️⃣ Configure Credentials

Create a file named `creds.txt` in the same directory as the script:

```
AWS_ACCESS_KEY_ID=<YOUR_ACCESS_KEY_ID>
AWS_SECRET_ACCESS_KEY=<YOUR_SECRET_ACCESS_KEY>
AWS_REGION=<YOUR_AWS_REGION>
ASSUME_ROLE_ARN=<OPTIONAL_ROLE_ARN>

```

> 💡 ASSUME_ROLE_ARN is optional.
> 
> 
> If not specified, the script will use the static credentials directly.
> 
> If provided, it will use STS to assume the given role temporarily.
> 

---

## 🚀 How to Run

Run the script from your terminal:

```bash
python secrets-reader.py

```

**What it does:**

1. Loads AWS credentials from `creds.txt`.
2. Initializes a session using those credentials.
3. (Optional) Assumes the IAM role if `ASSUME_ROLE_ARN` is specified.
4. Lists all available secrets in AWS Secrets Manager.
5. Prompts you to select a secret by **name or number**.
6. Retrieves and displays the secret value.

---

## 🧩 Example Output

```
Available Secrets in Secrets Manager:

1. MyAppSecret
2. DatabasePassword

Enter secret name (or number) to retrieve: 1

Secret Retrieved Successfully!

Secret Name: MyAppSecret
Secret Value: {"username":"dbadmin","password":"StrongPass123"}

```

---

## 🛡️ Security Notes

- Avoid committing your actual `creds.txt` to GitHub — it should be **.gitignored**.
- Use **IAM roles** (EC2, Lambda, etc.) instead of hardcoding credentials where possible.
- Keep **least privilege** policies for KMS and Secrets Manager access.
- Enable **CloudTrail** for auditing secret access events.

---

## 📜 Example IAM Policy

Attach this policy to your IAM user or role to grant access to the specific secret and key:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:ListSecrets",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "arn:aws:secretsmanager:ap-south-1:111122223333:secret:MyAppSecret-*"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:ap-south-1:111122223333:key/your-key-id"
    }
  ]
}

```

---

## 👥 Team Members

| Name | Role |
| --- | --- |
| User 1 | IAM User 1 / Team Member |
| User 2 | IAM User 2 / Team Member |
| User 3 | IAM User 3 / Team Member |

> Each user should have unique access credentials to test secure access.
> 

---

## 🧾 License

This project is for **educational and security demonstration** purposes only.

Ensure that all credentials and AWS resources are managed responsibly.

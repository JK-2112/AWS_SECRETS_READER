# 🔐 Secure Access to AWS Secrets Manager using **Cognito, STS, and IAM Roles**

This project demonstrates **secure, token-based access control** for AWS Secrets Manager secrets using **Amazon Cognito authentication** and **temporary AWS credentials** obtained through **AWS STS (Security Token Service)**.

Secrets are encrypted using **AWS KMS**, and access is controlled dynamically through **IAM roles** assigned via the **Cognito Identity Pool** based on the user’s role or group membership.

---

## 🧠 Overview

- **Goal:** Securely access AWS Secrets Manager secrets using Cognito authentication and temporary credentials issued via AWS STS.
- **Authentication:** Users log in via **Cognito User Pool**, receiving a secure token (JWT).
- **Authorization:** The token is sent to a **Cognito Identity Pool**, which decides the IAM role to assume (`SecretsLister` or `SecretsViewer`).
- **Secrets Encryption:** Managed using AWS **Key Management Service (KMS)**.
- **Language:** Python (using `boto3` and `botocore`).
- **Access Control:** Fine-grained control using IAM roles and temporary credentials — no long-term keys stored locally.

---

## ⚙️ Architecture

```
User (login)
   ↓
Cognito User Pool (authentication - username & password)
   ↓
Cognito Identity Pool (authorization - role mapping)
   ↓
AWS STS (issues temporary AWS credentials)
   ↓
IAM Role (SecretsLister / SecretsViewer)
   ↓
AWS Secrets Manager (list or view secrets)

```

- **SecretsLister Role:** Can list all secrets but cannot view their values.
- **SecretsViewer Role:** Can list and view secret values.

---

## 🧰 Prerequisites

Before running the script, ensure you have:

- A **Cognito User Pool** with registered users.
- A **Cognito Identity Pool** linked to that User Pool.
- Two IAM roles created:
    - `SecretsLister` (permission: `ListSecrets`)
    - `SecretsViewer` (permissions: `ListSecrets`, `GetSecretValue`)
- Identity Pool configured to:
    - Assign `SecretsLister` to all authenticated users by default.
    - Map Cognito group `SecretsViewerGroup` to IAM role `SecretsViewer`.
- A **Secrets Manager secret** encrypted with a **KMS key**.
- Python 3.x installed with dependencies:

```bash
pip install boto3 botocore

```

---

## 🧩 Key AWS Services Used

| Service | Purpose |
| --- | --- |
| **Cognito User Pool** | Authenticates users (username + password) |
| **Cognito Identity Pool** | Maps authenticated users to IAM roles |
| **AWS STS** | Issues temporary AWS credentials for the assumed IAM role |
| **IAM Roles** | Define what each user can do (Lister/Viewer) |
| **AWS Secrets Manager** | Stores encrypted secrets |
| **AWS KMS** | Encrypts and decrypts secrets securely |

---

## 🧠 Authentication & Authorization Flow

1. User logs in with username and password.
2. Cognito User Pool validates credentials and returns a **JWT ID token**.
3. The ID token is sent to the **Cognito Identity Pool**.
4. The Identity Pool verifies the token and maps the user to the correct **IAM role**.
5. **AWS STS** issues temporary credentials for that role.
6. The script uses these temporary credentials to access **Secrets Manager** securely.

---

## 🧰 Configuration Steps

### 1️⃣ Create Cognito User Pool

- Create a new **User Pool** in Cognito.
- Create and confirm test users (e.g., `testuser`, `testuser2`).

### 2️⃣ Create App Client

- Create a new **App Client** (without client secret for SRP auth).
- If you use a client secret, the script handles `SECRET_HASH` generation automatically.

### 3️⃣ Create Cognito Identity Pool

- Link it with your **User Pool** and **App Client**.
- Set:
    - **Authenticated Role:** `SecretsLister`
    - **Role Mapping:**
        - Group `SecretsViewerGroup` → Role `SecretsViewer`

### 4️⃣ Create IAM Roles

- **SecretsLister Role Policy:**
    
    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "secretsmanager:ListSecrets",
          "Resource": "*"
        }
      ]
    }
    
    ```
    
- **SecretsViewer Role Policy:**
    
    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "secretsmanager:ListSecrets",
            "secretsmanager:GetSecretValue"
          ],
          "Resource": "*"
        }
      ]
    }
    
    ```
    

---

## 🚀 How to Run

Run the script from your terminal:

```bash
python secrets-reader.py

```

When prompted:

- Enter your Cognito username and password.

The program will:

1. Authenticate you with Cognito.
2. Get temporary AWS credentials through STS.
3. Display your currently assumed IAM role.
4. List all secrets available to your role.
5. Let you choose one to view (if permitted).

---

## 🧩 Example Output

```
Enter username: testuser2
Enter password: *********

🔐 Authenticating user with Cognito...
✅ Authenticated Successfully!

🔄 Getting temporary AWS credentials via Cognito Identity...
✅ Temporary AWS Credentials Retrieved
🔍 Currently assumed role ARN: arn:aws:sts::991046440595:assumed-role/SecretsViewer/CognitoIdentityCredentials

📜 Available Secrets:
1. app/DatabaseSecret
2. app/ApiKey
3. app/ServiceCredentials

👉 Enter the number of the secret you want to view: 2

🔑 Secret Retrieved Successfully!
Secret Name: app/ApiKey
Secret Value: {"api_key": "a1b2c3d4e5f6g7"}

```

---

## 🛡️ Security Highlights

- ✅ **Token-based authentication:** No long-term AWS keys used.
- ✅ **STS temporary credentials:** Auto-expire within 1 hour.
- ✅ **Role-based access:** Access is determined by IAM role mapped via Cognito.
- ✅ **Least privilege:** Users only see secrets they are permitted to.
- ✅ **Auditable:** All actions logged via CloudTrail.

---

## 🧠 Troubleshooting

| Issue | Cause | Fix |
| --- | --- | --- |
| `NotAuthorizedException: SECRET_HASH was not received` | App client has a secret | Ensure your script computes `SECRET_HASH` |
| `AccessDeniedException` | User role lacks permission | Check IAM role and Identity Pool mapping |
| `ResourceNotFoundException` | Secret name is incorrect | Verify secret name or region |
| `The ambiguous role mapping rules...` | Conflicting Cognito role settings | Review Identity Pool “Role mapping” section |

---

## 👥 Team Members

| Name | Role |
| --- | --- |
| **Jeyanth Khanna R** | Cognito + STS Integration, IAM Role Configuration |
| **Team Member 2** | IAM Policy Management |
| **Team Member 3** | Secrets Manager & KMS Setup |

Each team member used individual Cognito accounts to test secure, role-based secret access.

---

## 🧾 License

This project is for **educational and security demonstration purposes only**.

Ensure AWS credentials, secrets, and keys are handled responsibly and not exposed publicly.

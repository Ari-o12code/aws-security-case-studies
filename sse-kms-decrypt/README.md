# SSE-KMS Access Control and CloudTrail Detection on S3

*Tested 26 October 2026 in us-east-1, with the AWS CLI in CloudShell.*

A role with `s3:GetObject` and no KMS permission read a file from a bucket encrypted with SSE-S3, and was denied the same file in a bucket encrypted with SSE-KMS under a customer managed key. CloudTrail recorded the denial as a KMS `Decrypt` event with `AccessDenied`, but that event names neither the object that was requested nor the caller's IP address. This case study covers the test, the events it produced, an alert on denied decrypts and a policy that limits decryption to requests made through S3.

## Setup

I uploaded the same fake KYC file, which holds a customer ID, a name and a BVN, to two buckets. The first bucket uses the default encryption, SSE-S3, and the second uses SSE-KMS with a customer managed key and S3 Bucket Key turned off.

I created the key and its alias as my admin user:

```bash
aws kms create-key --region us-east-1 --description "kms-lab: SSE-KMS writeup"
aws kms create-alias --region us-east-1 --alias-name alias/kms-lab --target-key-id <key-id>
```

The key has the default key policy, which gives the account root `kms:*`, so IAM policies decide who may use the key.

I then set that key as the default encryption for the second bucket, with Bucket Key off:

```bash
aws s3api put-bucket-encryption --bucket kmslab-ssekms-<suffix> --region us-east-1 \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"},"BucketKeyEnabled":false}]}'
```

The reader role, `kms-lab-reader`, has one inline policy that allows `s3:ListBucket` and `s3:GetObject` on both buckets and nothing else, so it has no KMS permission. An attacker holding a leaked credential or an over-scoped service role would have the same access. The role trusts the account, and I assumed it from my admin user with the session name `lab01`. Its policy is in [`policies/reader-policy.json`](policies/reader-policy.json) and its trust policy is in [`policies/trust-policy.json`](policies/trust-policy.json).

## Reading Both Files as the Role

As that role, I read the SSE-S3 file first:

```bash
aws s3 cp s3://kmslab-sses3-<suffix>/kyc-sample.csv -
```

The command printed the file with no error, although I did not save that output. Under SSE-S3, `s3:GetObject` is the only permission the read needs.

I then ran the same read against the SSE-KMS bucket, with the same role and permissions:

```bash
aws s3 cp s3://kmslab-ssekms-<suffix>/kyc-sample.csv -
```

The read failed with this error:

```
download failed: s3://kmslab-ssekms-<suffix>/kyc-sample.csv to - An error occurred (AccessDenied)
when calling the GetObject operation: User: arn:aws:sts::111122223333:assumed-role/kms-lab-reader/lab01
is not authorized to perform: kms:Decrypt on resource:
arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
because no identity-based policy allows the kms:Decrypt action
```

S3 authorized the request, and KMS denied the `kms:Decrypt` call that S3 made to decrypt the object.

I then added one statement to the role, which allows `kms:Decrypt` on that key only when the call comes through S3 in us-east-1. The statement is in [`policies/decrypt-via-s3.json`](policies/decrypt-via-s3.json) and is explained under Prevention. With it in place, the same read printed the file.

## CloudTrail Evidence

These events come from CloudTrail Event history in us-east-1, and the trimmed JSON is in [`evidence/`](evidence/).

| UTC, 26 Oct | Event | Identity | Result | Encryption context |
|---|---|---|---|---|
| 18:40:57 | `GenerateDataKey` | `user/iamadmin` (MFA) | allowed | `kmslab-ssekms-<suffix>/kyc-sample.csv` |
| 18:46:44 | `Decrypt`, two events | `assumed-role/kms-lab-reader/lab01` | **AccessDenied** | none recorded |
| 18:48:55 | `Decrypt`, two events | `assumed-role/kms-lab-reader/lab01` | allowed | `kmslab-ssekms-<suffix>/kyc-sample.csv` |

Every one of these events has `invokedBy` and `sourceIPAddress` set to `fas.s3.amazonaws.com`, because neither the role nor my admin user called KMS directly. S3 called KMS on their behalf through a [forward access session](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_forward_access_sessions.html). AWS still evaluates the original caller's permissions on both services, so the read succeeds only if the identity can read the object and use the key.

Three things a responder would want are missing from these events:

- The object read. A lookup for `GetObject` over the same window returned `0` events, because object reads are S3 data events. Event history holds management events only, and data events are recorded only by a trail that is configured to log them.
- The caller's IP address. The KMS events give `fas.s3.amazonaws.com` as the source, so the address the request came from appears only in the S3 data event for the same request.
- The object the denied request asked for. The denied `Decrypt` event has `requestParameters: null` and so carries no encryption context, while the allowed event names the object. A denied event therefore identifies the principal and the key, and does not identify the file.

The object ARN appears in the allowed events because Bucket Key was off. With an S3 Bucket Key, S3 uses the bucket ARN as the encryption context, so the KMS events record the bucket and no longer record the object. A Bucket Key reduces KMS request costs by up to 99 percent, according to the [S3 Bucket Keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html) documentation, so the choice trades KMS cost against the ability to tell from KMS events which object was decrypted.

Each read produced two `Decrypt` events in the same second with different request IDs, although I ran each read once. I have not found out why.

## Detection

The event to alert on is a KMS `Decrypt` with `errorCode` `AccessDenied` against a key that protects sensitive data, with the principal named in the alert. A single denial can come from a misconfigured job, whereas a denial from a role that has never used the key should be investigated the same day.

Both versions below need a CloudTrail trail, because Event history cannot trigger alerts. I have not run either of them yet.

The first is an EventBridge rule pattern:

```json
{
  "source": ["aws.kms"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["kms.amazonaws.com"],
    "eventName": ["Decrypt"],
    "errorCode": ["AccessDenied"]
  }
}
```

`Decrypt` is a read-only management event, so the rule matches only when its state is `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`. A rule in the `ENABLED` state does not receive read-only events, as the [EventBridge docs](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html) explain.

The second is an Athena query over a table built on the trail's logs:

```sql
SELECT eventtime,
       useridentity.arn AS principal,
       useridentity.invokedby AS via,
       errormessage
FROM cloudtrail_logs
WHERE eventsource = 'kms.amazonaws.com'
  AND eventname = 'Decrypt'
  AND errorcode = 'AccessDenied'
ORDER BY eventtime DESC;
```

## Prevention

Two controls together stop `s3:GetObject` alone from being enough to read the file.

The first is to encrypt with a customer managed key in place of the AWS managed key `aws/s3`. The AWS managed key can be used through S3 by any principal in the account, as this [AWS re:Post answer](https://www.repost.aws/questions/QUUFBF6OvvREuaXKzRurcPQA/why-can-s3-access-the-kms-key-resource-under-my-account) explains, so a role with `s3:GetObject` can read the file with no second authorization. With a customer managed key, `kms:Decrypt` is a separate permission that has to be granted.

The second is to grant `kms:Decrypt` only for requests made through S3:

```json
{
  "Sid": "DecryptOnlyThroughS3",
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
  "Condition": { "StringEquals": { "kms:ViaService": "s3.us-east-1.amazonaws.com" } }
}
```

With the `kms:ViaService` condition, the role can decrypt only as part of an S3 request and cannot call `kms:Decrypt` on the key directly.

These controls have two limits. Stolen credentials for the role can still read whatever its S3 permissions allow, so those permissions should be as narrow as the key grant. The default key policy also delegates the decision to IAM, which means anyone who can edit IAM policies can grant `kms:Decrypt`. For real customer data I would name the allowed roles in the key policy itself, so that the key's administrators decide who can decrypt. I will write that control in Terraform when my lab organization is built.

## Business Cost

If a bucket of KYC documents is encrypted with SSE-S3, any credential with `s3:GetObject` on it can download every customer's ID documents and BVN, whether the credential belongs to an analytics job or was leaked from CI. The business then has to notify its customers and the data protection regulator. If the bucket uses a customer managed key and `kms:Decrypt` is granted only to the service that needs it, the same credential receives `AccessDenied`, and CloudTrail records the denial with the role's name.

## Next Check

I would repeat the reads with S3 data events turned on, which would pair each `Decrypt` event with its `GetObject` event, record the caller's IP address, and might show where the second `Decrypt` event comes from.

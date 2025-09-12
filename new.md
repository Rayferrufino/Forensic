
---

### **Initial Alert Review (CloudTrail Event-Based)**

Gather all relevant CloudTrail log fields to confirm and enrich the alert. Include:

* `eventName`: `RunInstances`
* `userIdentity`: IAM user or role
* `sourceIPAddress`, `userAgent`
* `awsRegion`
* `responseElements.instancesSet.items[0].instanceId`
* `requestParameters.imageId`, `instanceType`, etc.

---

### **Escalate to AWS Account Owners or CloudOps**


* Immediately escalate to the **Cloud Infrastructure or DevOps team** that owns AWS account permissions
* Provide a **pre-written takedown request template**
  
#### Example Escalation Message to CloudOps:

>  **Emergency: Suspected Malicious EC2 Instance Detected**
>
> An EC2 instance (`i-xxxxxxxxxx`) was created via suspicious activity:
>
> * **Account:** 123456789012
> * **Region:** us-east-1
> * **User Agent:** Boto3/Linux
> * **Source IP:** `92.113.xxx.xxx`
> * **IAM Role:** `unknown-assume-role`
>
> Please perform the following ASAP:
>
> 1. Isolate instance to **quarantine security group**
> 2. Detach IAM roles
> 3. Snapshot volume for DFIR (optional)
> 4. Terminate the instance
>
> Full CloudTrail event and metadata attached.

---

### Step 6: **Document and Monitor**

Ensure these artifacts are created/stored:

* CloudTrail logs with full event detail
* List of actions taken (by whom, when)
* Forensic snapshot IDs
* IAM entities involved
* Tags / UserData used by the attacker
* Timeline of attacker activity

---

##  Summary Table

| Step | Action                                | Who Executes          |
| ---- | ------------------------------------- | --------------------- |
| 1    | Confirm alert details from CloudTrail | IR Analyst            |
| 2    | Escalate takedown to CloudOps         | IR Analyst            |
| 3    | Trigger SSM / Lambda if available     | Automation / CloudSec |
| 4    | Snapshot EBS, gather metadata         | CloudOps              |
| 5    | Terminate instance                    | CloudOps              |
| 6    | Document and close                    | IR Analyst / DFIR     |

---


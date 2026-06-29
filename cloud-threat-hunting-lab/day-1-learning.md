# Day 1: AWS CloudTrail Basics

## What is CloudTrail?
CloudTrail is an AWS service that records API calls and events made on your AWS account. It's like an audit log for everything happening in AWS.

## What does it log?
- User creation/deletion
- Resource creation (EC2, S3, etc.)
- Policy changes
- Authentication attempts
- Failed actions

## Where are logs stored?
In an S3 bucket that you specify when creating the trail.

## Why is this useful for security?
- Detect unauthorized changes
- Investigate incidents
- Audit who did what and when
- Identify suspicious activity

## What I did today:
1. Created AWS account
2. Enabled CloudTrail to log events
3. Created resources to generate events
4. Verified CloudTrail captured all events

## Next steps:
- Write KQL queries to detect suspicious activity
- Connect CloudTrail logs to Sentinel
- Build threat hunting scenarios

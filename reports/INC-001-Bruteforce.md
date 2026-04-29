# Incident ID: INC-001

## Title
Multiple Failed Login Attempts Followed by Successful Authentication

## Severity
Medium

## Summary
Five or more failed logon attempts were followed by a successful authentication event. This can indicate brute-force or password guessing behavior.

## Evidence
- EventCode 4625 (Failed Login)
- EventCode 4624 (Successful Login)

## MITRE ATT&CK
- T1110 Brute Force
- T1078 Valid Accounts

## Verdict
Controlled benign test activity in home SOC lab.

## Recommendation
Tune thresholds and correlate source IP activity.

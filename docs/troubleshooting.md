# Troubleshooting

## Issue
Sysmon logs not visible in Splunk.

## Root Cause
Access denied while subscribing to Sysmon channel (errorCode=5).

## Fix
Adjusted service permissions / Local System account and restarted forwarder.

## Result
Sysmon logs ingested successfully.

# Cognito Post-Authentication Lambda

This AWS Lambda function, `CognitoPostAuthenticationHandler`, is designed to handle post-authentication events in an AWS Cognito user pool. It updates user attributes based on specific conditions, such as user authentication through Facebook.

## Overview

When a post-authentication event is triggered in the Cognito user pool, this Lambda function intercepts the event and executes the following actions:

1. Checks if the trigger source is a specific post-authentication event.
2. Updates user attributes, such as email verification status, based on certain conditions.

## Usage

### Configuration

Before using this Lambda function, ensure the following environment variables are set:

- `ACCESS_KEY_ID`: AWS access key ID.
- `ACCESS_KEY_SECRET`: AWS secret access key.
- `USER_POOL_ID`: ID of the Cognito user pool.
- `REGION_NAME`: AWS region name.

### Trigger

This Lambda function is triggered by post-authentication events in the Cognito user pool.

### Dependencies

This Lambda function relies on the AWS SDK for Java to interact with the Cognito Identity Provider.

### Deployment

To deploy this Lambda function, package the code along with its dependencies using Maven and the Maven Shade plugin. Then, upload the deployment package to AWS Lambda.

### Execution

When a post-authentication event occurs, AWS Cognito invokes this Lambda function. The function processes the event, updates user attributes as necessary, and returns the unmodified event.

## Code Structure

- `CognitoPostAuthenticationHandler`: Main class representing the Lambda function.
- `handleRequest`: Method to handle post-authentication events.
- `getAWSCognitoIdentityProvider`: Method to retrieve the AWS Cognito Identity Provider client.
- `updateUserAttributes`: Method to update user attributes in the Cognito user pool.

## Conclusion

This Lambda function enhances the functionality of AWS Cognito by allowing developers to customize user attribute updates based on specific conditions. It provides flexibility and control over user management in Cognito user pools, improving the overall user experience.


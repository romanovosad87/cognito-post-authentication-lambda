package example;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AdminUpdateUserAttributesRequest;
import com.amazonaws.services.cognitoidp.model.AdminUpdateUserAttributesResult;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.events.CognitoUserPoolPostAuthenticationEvent;
import org.json.JSONObject;
import java.util.Map;

/**
 * This class represents a Cognito post-authentication handler responsible for handling
 * post-authentication events in a Cognito user pool.
 * <p>
 * The class uses the AWS Cognito Identity Provider to interact with the Cognito user pool.
 */
public class CognitoPostAuthenticationHandler {
    private static final String ACCESS_KEY_ID = System.getenv("ACCESS_KEY_ID");
    private static final String ACCESS_KEY_SECRET = System.getenv("ACCESS_KEY_SECRET");
    private static final String USER_POOL_ID = System.getenv("USER_POOL_ID");
    private static final String REGION_NAME = System.getenv("REGION_NAME");
    private static final String TRIGGER_SOURCE = "PostAuthentication_Authentication";
    private static final String IDENTITIES = "identities";
    private static final String FACEBOOK = "Facebook";
    private static final String EMAIL_VERIFIED = "email_verified";
    private static final String EMAIL = "email";
    private static final String TRUE = "true";

    /**
     * Handles the post-authentication event for a Cognito user pool.
     * This method is invoked when a post-authentication event occurs in the Cognito user pool.
     * It checks if the trigger source is a specific post-authentication event and updates user attributes based on certain conditions.
     *
     * @param event   The post-authentication event received from the Cognito user pool.
     * @param context The AWS Lambda context object.
     * @return The unmodified post-authentication event.
     */
    public CognitoUserPoolPostAuthenticationEvent handleRequest(
            CognitoUserPoolPostAuthenticationEvent event, Context context) {
        LambdaLogger logger = context.getLogger();
        logger.log("Function '" + context.getFunctionName() + "' called");
        logger.log("TriggerSource: " + event.getTriggerSource());

        if (event.getTriggerSource().equals(TRIGGER_SOURCE)) {
            if (event.getRequest().getUserAttributes().get(EMAIL) != null) {
                Map<String, String> userAttributes = event.getRequest().getUserAttributes();
                JSONObject jsonObject = new JSONObject(userAttributes);
                if (!jsonObject.isNull(IDENTITIES)) {
                    String identities = jsonObject.getString(IDENTITIES);
                    logger.log("providerName " + identities);
                    if (identities.contains(FACEBOOK)) {
                        updateUserAttributes(event.getUserName(), logger);
                    }
                }
            }
        }
        logger.log("Username: " + event.getUserName());
        return event;
    }

    /**
     * Returns an instance of the AWS Cognito Identity Provider client.
     *
     * @return An instance of the AWS Cognito Identity Provider client.
     */
    private AWSCognitoIdentityProvider getAWSCognitoIdentityProvider() {
        final BasicAWSCredentials basicAWSCredentials = new BasicAWSCredentials(ACCESS_KEY_ID,
                ACCESS_KEY_SECRET);

        return AWSCognitoIdentityProviderClientBuilder.standard()
                .withCredentials(new AWSStaticCredentialsProvider(basicAWSCredentials))
                .withRegion(REGION_NAME)
                .build();
    }

    /**
     * Updates user attributes in the Cognito user pool.
     * This method is invoked to update specific user attributes based on certain conditions, such as user authentication through Facebook.
     *
     * @param username The username of the user.
     * @param logger   The Lambda logger object.
     */
    private void updateUserAttributes(String username, LambdaLogger logger) {
        AdminUpdateUserAttributesRequest request = new AdminUpdateUserAttributesRequest()
                .withUsername(username)
                .withUserPoolId(USER_POOL_ID)
                .withUserAttributes(new AttributeType().withName(EMAIL_VERIFIED).withValue(TRUE));
        AWSCognitoIdentityProvider awsCognitoIdentityProvider = getAWSCognitoIdentityProvider();
        AdminUpdateUserAttributesResult result
                = awsCognitoIdentityProvider.adminUpdateUserAttributes(request);
        logger.log(String.format("AdminUpdateUserAttributesResult, status code: %s",
                result.getSdkHttpMetadata().getHttpStatusCode()));
    }
}

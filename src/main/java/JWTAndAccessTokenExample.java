import com.jayway.jsonpath.JsonPath;
import okhttp3.*;
import org.apache.commons.codec.binary.Base64;
import java.io.*;
import java.security.*;
import java.text.MessageFormat;

public class JWTAndAccessTokenExample {

    /*
    SalesForce Documentation - OAuth 2.0 JWT Bearer Flow for Server-to-Server Integration
    https://help.salesforce.com/articleView?id=remoteaccess_oauth_jwt_flow.htm&type=0

    Below are the steps I followed to build SalesForce integration using a connected app and JWT authentication.

    Create a Connected App.
    - Login to SalesForce.
    - Navigate to Setup -> Apps -> App Manager -> New Connected App.
    - Fill out the required fields.
    - Tick "Enable OAuth Settings."
    - Tick "Enable for Device Flow."
    - Select "Access and manage your data (api)" and "Perform requests on your behalf at any time (refresh_token, offline_access)" for OAuth Scopes.
    - Save.

    Generate Certificate
    - Navigate to Setup -> Security -> Certificate and Key Management.
    - Create a Self-Signed Certificate.
    - Export certificate to keystore.
    - Download the certificate.

    Add the certificate to the connected app.
    - Navigate to Setup -> Apps -> App Manager -> Your Connected App -> Edit.
    - Tick "Use digital signatures" and upload your self-signed certificate.

    Change App Policies
    - Edit Policies for the connected app.
    - Set Permitted Users to All users may self-authorize.
    - Set IP Relaxation to Relax IP restrictions.

    Authorize Application
    - Based on the answer here https://salesforce.stackexchange.com/a/93948, you need to authorize the application at least once.
    - To authorize the connected app hit following link and allow access for connected app to your SalesForce account:
    https://login.salesforce.com/services/oauth2/authorize?client_id=[clientId]&redirect_uri=[redirectUri]&response_type=code

    You are good to go!
    Run below to generate JWT token and obtain access token.
    */

    private final static String certAlias = "certalias";
    private final static String jksFile = "./keystore.jks";
    private final static String keystorePassword = "password"; // the password you used when exported certificate to the keystore

    public static void main(String[] args) {

        String header = "{\"alg\":\"RS256\"}";
        // String claimTemplate = "'{'\"iss\": \"{0}\", \"sub\": \"{1}\", \"aud\": \"{2}\", \"exp\": \"{3}\", \"jti\": \"{4}\"'}'";
        String claimTemplate = "'{'\"iss\": \"{0}\", \"sub\": \"{1}\", \"aud\": \"{2}\", \"exp\": \"{3}\"'}'"; // SalesForce does not require jti

        try {
            StringBuffer token = new StringBuffer();

            // Encode the JWT Header and add it to our string to sign
            token.append(Base64.encodeBase64URLSafeString(header.getBytes("UTF-8")));

            // Separate with a period
            token.append(".");

            // Create the JWT Claims Object
            String[] claimArray = new String[4];
            claimArray[0] = "3MVG99OxTyEMCQ3gNp2PjkqeZKxnmAiG1xV4oHh9AKL_rSK.BoSVPGZHQukXnVjzRgSuQqGn75NL7yfkQcyy7";
            claimArray[1] = "my@email.com";
            claimArray[2] = "https://login.salesforce.com";
            claimArray[3] = Long.toString( ( System.currentTimeMillis()/1000 ) + 300);
            // claimArray[4] = "";
            MessageFormat claims;
            claims = new MessageFormat(claimTemplate);
            String payload = claims.format(claimArray);

            // Add the encoded claims object
            token.append(Base64.encodeBase64URLSafeString(payload.getBytes("UTF-8")));

            // Load the private key from a keystore
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream(jksFile), keystorePassword.toCharArray());
            PrivateKey privateKey = (PrivateKey) keystore.getKey(certAlias, keystorePassword.toCharArray());

            // Sign the JWT Header + "." + JWT Claims Object
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(token.toString().getBytes("UTF-8"));
            String signedPayload = Base64.encodeBase64URLSafeString(signature.sign());

            // Separate with a period
            token.append(".");

            // Add the encoded signature
            token.append(signedPayload);

            System.out.println("JWT Token: " + token.toString());

            // Use above JWT to get access token
            OkHttpClient client = new OkHttpClient();
            RequestBody formBody = new FormBody.Builder()
                    .add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                    .add("assertion", token.toString())
                    .build();
            Request request = new Request.Builder().url("https://login.salesforce.com/services/oauth2/token").post(formBody).build();
            Response response = client.newCall(request).execute();
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected code " + response);
            }
            String responseBody = response.body().string();
            System.out.println("Response Body: " + responseBody);

            String accessToken = JsonPath.parse(responseBody).read("$.access_token");
            System.out.println("Access Token: " + accessToken);

            String instanceUrl = JsonPath.parse(responseBody).read("$.instance_url");
            System.out.println("Instance URL: " + instanceUrl);

            // Get an Account object using access token
            request = new Request.Builder()
                    .url("https://na81.salesforce.com/services/data/v37.0/sobjects/Account/")
                    .header("Authorization", "Bearer " + accessToken)
                    .get().build();
            response = client.newCall(request).execute();
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected code " + response);
            }
            System.out.println("Account Object: " + response.body().string());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

package edu.Osayd.min_jwt.util;


import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

public class JwtSecretGenerator {

    /*
    Purpose: Utility class to help generate a secure base64-encoded JWT secret.
        -Key Functions: Uses SecureRandom and Base64 to generate strong keys.

    Security Role:
        -Helps developers generate proper signing keys — essential to JWT security.
        -Only used manually at development time (not part of runtime app).
     */
    public static void main(String[] args) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
        keyGen.init(256); // for HS256
        SecretKey secretKey = keyGen.generateKey();
        String base64Key = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        System.out.println("Your JWT Secret Key: " + base64Key);
    }
}

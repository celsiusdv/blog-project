package com.blog.security;

import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/*token generated with asymmetric cipher (not secret key)
* this class generates:
   - public key
   - private key
*the generated key is used in SecurityConfig.class in the following methods:
   - jwtDecoder(){}
   - jwtEncoder(){}
*/
@Component
public class KeyProperties {
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    public KeyProperties(){
        KeyPair pair = this.generateRsaKey();
        this.publicKey = (RSAPublicKey) pair.getPublic();
        this.privateKey = (RSAPrivateKey) pair.getPrivate();
    }

    public RSAPublicKey getPublicKey(){return this.publicKey;}
    public RSAPrivateKey getPrivateKey(){return this.privateKey;}


    //generate the public and private key
    public KeyPair generateRsaKey(){
        KeyPair keyPair;
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();

            return keyPair;

        }catch( NoSuchAlgorithmException e){throw new RuntimeException(e.getCause());}
    }
}

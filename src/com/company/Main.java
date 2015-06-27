package com.company;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Main
{
    private static byte[ ] packKeyAndIv(
            Key	            key,
            IvParameterSpec ivSpec)throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        bOut.write(ivSpec.getIV());
        bOut.write(key.getEncoded());

        return bOut.toByteArray();
    }

    private static Object [ ] unpackKeyAndIV( byte[]    data) {

        byte[]    keyD = new byte[16];
        byte[]    iv = new byte[data.length - 16];

        return new Object[] {
                new SecretKeySpec(data, 16, data.length - 16, "AES"),
                new IvParameterSpec(data, 0, 16)
        };


    }

    public static void main(String[] args) throws Exception{

        byte[ ]           input = new byte[ ] { 0x00, (byte)0xab, (byte)0xcd };


        // create the RSA Key
        Cipher cipher = Cipher.getInstance("RSA/NONE/NoPadding", "BC");
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024, random);
        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();

        // create the symmetric key and iv
        Key sKey = CryptoUtils.createAESKey(256, random);
        IvParameterSpec sIvSpec = CryptoUtils.createAESCtrIv(random);





        // symmetric key/iv wrapping step
        Cipher xCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        xCipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] keyBlock = packKeyAndIv(sKey, sIvSpec);
        byte[] encryptedKeyBlock = xCipher.doFinal(keyBlock);


        // encryption step
        System.out.println("input: " + CryptoUtils.toHex(input));
        Cipher sCipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        sCipher.init(Cipher.ENCRYPT_MODE, sKey, sIvSpec);
        byte[] encryptedInput = sCipher.doFinal(input);
        System.out.println("encrypted: " + CryptoUtils.toHex(encryptedInput));



        // symmetric key/iv unwrapping step
        Cipher lCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        lCipher.init(Cipher.DECRYPT_MODE, privKey, random);
        byte[] newKeyBlock = packKeyAndIv(sKey, sIvSpec);
        byte[] decryptedKeyBlock = xCipher.doFinal(keyBlock);


        // decryption step
    }
}

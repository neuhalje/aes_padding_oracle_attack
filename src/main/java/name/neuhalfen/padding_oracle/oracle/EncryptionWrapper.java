package name.neuhalfen.padding_oracle.oracle;

import name.neuhalfen.padding_oracle.CipherText;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class EncryptionWrapper {
    private static final int AES_KEYLEN_IN_BITS = 128;
    private static final int AES_BLOCKLEN_IN_BYTES = 16;

    private final SecretKey secretKey;

    public EncryptionWrapper(String key) throws InvalidKeySpecException, NoSuchAlgorithmException {
        this(key.toCharArray());
    }
    public EncryptionWrapper(char[] key) throws InvalidKeySpecException, NoSuchAlgorithmException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] salt = new byte[] {1,2,4,6,7}; // "random"
        KeySpec spec = new PBEKeySpec(key,salt,100, AES_KEYLEN_IN_BITS);
        secretKey = factory.generateSecret(spec);
    }


    public CipherText encrypt(byte[] plaintext) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, BadPaddingException, IllegalBlockSizeException {

        // Encrypt the plaintext
        SecretKey secretKeyInAESFormat = new SecretKeySpec(secretKey.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeyInAESFormat);
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = cipher.doFinal(plaintext);


        // Sign the plaintext
        SecretKeySpec signingKey = new SecretKeySpec(secretKey.getEncoded(), "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signingKey);
        byte[] hmac = mac.doFinal(plaintext);

        return new CipherText(iv, ciphertext, hmac);
    }

    /**
     * Does not check signature!
     *
     * @param ciphertext See encrypt.
     * @return plaintext
     */
    public byte[] decrypt(CipherText ciphertext) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {
        SecretKey secretKeyInAESFormat = new SecretKeySpec(secretKey.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeyInAESFormat, new IvParameterSpec(ciphertext.iv));
        byte[] plaintext = cipher.doFinal(ciphertext.ciphertext);

        return plaintext;
    }


    public boolean isSignatureCorrect(byte[] toBeChecked, byte[] hmacSignature) throws NoSuchAlgorithmException, InvalidKeyException {
        // Sign
        SecretKeySpec signingKey = new SecretKeySpec(secretKey.getEncoded(), "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signingKey);
        byte[] hmac = mac.doFinal(toBeChecked);

        return Arrays.equals(hmac, hmacSignature);
    }

    public int getBlockLengthInBytes() {
        return AES_BLOCKLEN_IN_BYTES;
    }
}

package name.neuhalfen.padding_oracle.oracle;

import name.neuhalfen.padding_oracle.CipherText;

import javax.crypto.BadPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

/**
 * TODO
 */
public class PaddingOracle {

    public static enum VerificationResult {
        OK,
        MAC_INVALID,
        PADDING_INVALID
    }

    private final EncryptionWrapper encryptionWrapper;
    private final String secretMessage;


    PaddingOracle(EncryptionWrapper encryptionWrapper, String secretMessage) throws GeneralSecurityException {
        this.encryptionWrapper = encryptionWrapper;
        this.secretMessage = secretMessage;
    }


    public CipherText interceptCipherText() throws GeneralSecurityException {

        try {
            return encryptionWrapper.encrypt(this.secretMessage.getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            // "should not happen"
            throw new RuntimeException(e);
        }
    }

    public VerificationResult replayCiphertext(CipherText cipherText) throws GeneralSecurityException {

        try {
            final byte[] plaintext = encryptionWrapper.decrypt(cipherText);
            boolean isCorrectSignature = encryptionWrapper.isSignatureCorrect(plaintext, cipherText.hmac);

            return isCorrectSignature ? VerificationResult.OK : VerificationResult.MAC_INVALID;
        } catch (BadPaddingException e) {
            return VerificationResult.PADDING_INVALID;
        }
    }

    public boolean isPlaintext(String guessedPlaintext) {
        return guessedPlaintext.equals(this.secretMessage);
    }

    public int getBlockLengthInBytes() {
        return encryptionWrapper.getBlockLengthInBytes();
    }
}

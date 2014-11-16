package name.neuhalfen.padding_oracle.oracle;

import javax.xml.bind.DatatypeConverter;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * TODO
 */
public class PaddingOracleFactory {

    /**
     * Creates a new oracle with a random secret, and random plaintext.
     * @return new Oracle
     * @throws GeneralSecurityException
     */
    public static PaddingOracle newRandomOracle() throws GeneralSecurityException {

        final char[] key = randomString(16).toCharArray();

        final EncryptionWrapper wrapper = new EncryptionWrapper(key);

        final String secretMessage = PaddingOracleFactory.randomString(45);
        return new PaddingOracle(wrapper, secretMessage);
    }

    /**
     * Creates a new oracle with a random secret, and the passed in plaintext.
     * @return new Oracle
     * @throws GeneralSecurityException
     */
    public static PaddingOracle newOracleWithKnownText(String plaintext) throws GeneralSecurityException {

        final char[] key = randomString(16).toCharArray();

        final EncryptionWrapper wrapper = new EncryptionWrapper(key);

        return new PaddingOracle(wrapper, plaintext);
    }


    /**
     * Creates a random String of printable ASCII characters.
     *
     * @param len
     * @return a String with len characters
     */
     static String randomString(int len) {

        SecureRandom rnd = new SecureRandom();

        byte[] randomBytes = new byte[len];
        rnd.nextBytes(randomBytes);

        return DatatypeConverter.printBase64Binary(randomBytes).substring(0, len);
    }

}

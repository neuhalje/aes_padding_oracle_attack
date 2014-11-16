package name.neuhalfen.padding_oracle.cbc

import name.neuhalfen.padding_oracle.oracle.EncryptionWrapper
import spock.lang.Unroll

/**
 * The following tests demonstrate how the CBC mode can be used to modify ciphertext encrypted with (AES-)CBC to tamper the result of the decryption.
 *
 * All examples require that the plaintext of the to be tampered block is known.
 *
 * Examples are
 * <ul>
 *     <li>Modify the ciphertext to replace characters in the decrypted plaintext</li>
 *     <li>Modify the padding of the decrypted plaintext</li>
 * </ul>
 *
 * @see <a href="https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher-block_chaining_.28CBC.29">CBC Mode</a>
 * @see <a href="https://en.wikipedia.org/wiki/Padding_(cryptography)">Padding</a>
 */
class DemonstrateCBCTest extends spock.lang.Specification {

    final byte[] FIRST_BLOCK_PLAINTEXT = "1234567890abcdef".getBytes("US-ASCII")
    final byte[] SECOND_BLOCK_PLAINTEXT = "plain".getBytes("US-ASCII")

    /**
     *  Two blocks of plaintext. The second block does not align with the AES blocksize, thus requiring a padding.
     */
    final byte[] PLAINTEXT = ((FIRST_BLOCK_PLAINTEXT as List) + (SECOND_BLOCK_PLAINTEXT as List)).toArray(new byte[0])

    final char[] RANDOM_PASSWORD = "s3cr3t".getChars()

    def "cleverly patching a block of ciphertext allows us to manipulate the decrypted plaintext"() {

        given: "some CBC encrypted ciphertext, and the plaintext of a block"

        def sut = new EncryptionWrapper(RANDOM_PASSWORD)
        def encrypted = sut.encrypt(PLAINTEXT)

        when: "we patch ciphertext of the first block with the knowledge of the second blocks plaintext"

        byte known_plaintext_first_char = SECOND_BLOCK_PLAINTEXT[0]
        byte new_first_char = (byte) 'x'

        // The last step of CBC decryption for block n ("C[n]" - ciphertext block at position n)
        // is to XOR C[n-1] with the decrypted block C[n].
        // Tampering with the first byte of C[n-1] means
        //
        // * the decryption of block C[n-1] will be garbage
        //
        // * the decrypted plaintext of block C[n] will have its first character changed
        //   to plaintext_first_char ^ (first char of C[n-1]).
        //   Setting the first char of C[n-1] to "known_plaintext_first_char ^ new_first_char" gives
        //   "known_plaintext_first_char ^ known_plaintext_first_char ^ new_first_char"
        //   and this results in "new_first_char" being the first character of the decrypted result.
        encrypted.ciphertext[0] ^= known_plaintext_first_char ^ new_first_char


        then: "we have forced the plaintext of the second block to a value of our choosing"

        def decrypted = sut.decrypt(encrypted)

        // The first block is corrupted, but the second block should start with 'x'
        // bc. the first ciphertext block is XORed into the second block as last step of decryption
        def actual = new String(decrypted, FIRST_BLOCK_PLAINTEXT.length, SECOND_BLOCK_PLAINTEXT.length, "US-ASCII")
        "xlain" == actual
    }

    /**
     * This test builds on the previous test by patching each of the characters.
     */
    @Unroll
    def "manipulate the decrypted plaintext: patch ciphertext at #manipulateAt in 'plain' gives '#expected'"() {

        given: "some CBC encrypted ciphertext, and the plaintext of a block"

        def sut = new EncryptionWrapper(RANDOM_PASSWORD)
        def encrypted = sut.encrypt(PLAINTEXT)

        when: "we patch ciphertext of the first block with the knowledge of the second blocks plaintext"

        byte known_plaintext_char = SECOND_BLOCK_PLAINTEXT[manipulateAt]
        byte new_char = (byte) 'X'
        encrypted.ciphertext[manipulateAt] ^= new_char ^ known_plaintext_char

        then: "we have forced the plaintext of the second block to a value of our choosing"

        def decrypted = sut.decrypt(encrypted)

        // The first block is corrupted, but the second block have 'X' patched in
        def actual = new String(decrypted, FIRST_BLOCK_PLAINTEXT.length, SECOND_BLOCK_PLAINTEXT.length, "US-ASCII")
        actual == expected

        where:
        manipulateAt << [0, 1, 2, 3, 4]
        expected << ["Xlain", "pXain", "plXin", "plaXn", "plaiX"]
    }


    def "The last byte of padding can be patched to 0x1 to change the padding (when we know the real padding length)"() {

        given: "some plaintext that needs #real_padding bytes of padding for the AES block size"
        def sut = new EncryptionWrapper(RANDOM_PASSWORD)
        def encrypted = sut.encrypt(PLAINTEXT)
        byte real_padding = sut.blockLengthInBytes - SECOND_BLOCK_PLAINTEXT.length;

        when: "the last byte of the last block is manipulated to decrypt to 0x01"

        byte tampered_padding = 0x1;

        encrypted.ciphertext[FIRST_BLOCK_PLAINTEXT.length - 1] ^= real_padding ^ tampered_padding

        def decrypted = sut.decrypt(encrypted)

        then: "0x01 is interpreted as padding, and thus the original PKC#5 padding is part of the decrypted plaintext"
        // The first block is corrupted, but the second block should end with  real_padding times the byte value of real_padding
        decrypted.length == 2 * sut.blockLengthInBytes - 1 // The last byte is padding and thus removed by decryption

        for (int idx = decrypted.length - real_padding + 1; idx < decrypted.length - 1; idx++) {
            assert decrypted[idx] == real_padding
        }
    }
}

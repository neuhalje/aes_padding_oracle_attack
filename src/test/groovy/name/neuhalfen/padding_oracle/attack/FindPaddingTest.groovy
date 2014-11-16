package name.neuhalfen.padding_oracle.attack

import name.neuhalfen.padding_oracle.oracle.PaddingOracleFactory
import spock.lang.Unroll

class FindPaddingTest extends spock.lang.Specification {

    final String PLAINTEXT_THE_SIZE_OF_AES_AN_BLOCK = "1234567890abcdef"

    @Unroll
    def "the attack guesses the padding of #length"() {

        given:
        int lastBlockLength = 16 - length
        def plaintextSecondBlock = PLAINTEXT_THE_SIZE_OF_AES_AN_BLOCK.substring(0, lastBlockLength)
        def oracle = PaddingOracleFactory.newOracleWithKnownText(PLAINTEXT_THE_SIZE_OF_AES_AN_BLOCK + plaintextSecondBlock)

        def sut = new FindPadding()

        when:
        def padLen = sut.guessPaddingLen(oracle)

        then:
        padLen == length

        where:
        length << (1..15)
    }


    def "the attack guesses the padding for texts that are aligned to blocksize"() {

        given:
        def plaintextSecondBlock = PLAINTEXT_THE_SIZE_OF_AES_AN_BLOCK
        def oracle = PaddingOracleFactory.newOracleWithKnownText(PLAINTEXT_THE_SIZE_OF_AES_AN_BLOCK + plaintextSecondBlock)

        def sut = new FindPadding()

        when:
        def padLen = sut.guessPaddingLen(oracle)

        then:
        // Texts that are aligned to the blocksize have a complete block of padding appended
        padLen == 16
        oracle.interceptCipherText().ciphertext.length == 3 * 16
    }
}

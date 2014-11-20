package name.neuhalfen.padding_oracle.attack

import name.neuhalfen.padding_oracle.CipherText
import name.neuhalfen.padding_oracle.oracle.PaddingOracle
import name.neuhalfen.padding_oracle.oracle.PaddingOracleFactory
import spock.lang.Unroll

class DecipherBlockAttackTest extends spock.lang.Specification {

    final String PLAINTEXT_THE_SIZE_OF_AES_AN_BLOCK = "1234567890abcdef"

    @Unroll
    def "the attack guesses the content of a block with #paddingLength bytes padding"() {

        given:
        int lastBlockLength = 16 - paddingLength
        def plaintextSecondBlock = PLAINTEXT_THE_SIZE_OF_AES_AN_BLOCK.substring(0, lastBlockLength)
        def oracle = PaddingOracleFactory.newOracleWithKnownText(PLAINTEXT_THE_SIZE_OF_AES_AN_BLOCK + plaintextSecondBlock)

        def sut = new DecipherBlockAttack(oracle, oracle.interceptCipherText(), 1);

        when:
        byte[] plaintextWithPadding = sut.decrypt()

        // Strip padding
        byte[] plaintext = new byte[lastBlockLength];
        System.arraycopy(plaintextWithPadding, 0, plaintext, 0, lastBlockLength)

        then:
        plaintext == plaintextSecondBlock.bytes

        where:
        paddingLength << (1..15)
    }

    @Unroll
    def "setPadding(#padding)"() {
        given:
        def int numBlocks = 2

        // two blocks
        def originalCipherText = new CipherText(new byte[0], new byte[numBlocks * 16], new byte[0])
        def sut = new DecipherBlockAttack(Mock(PaddingOracle), originalCipherText, (numBlocks - 1))

        when:
        sut.setPadding(originalCipherText, (byte) padding)

        then: "the *known* padding is set: the last padding-1 bytes are set to padding"

        def paddingBlockStart = (numBlocks - 2) * 16
        for (int i = (16 - padding + 1); i < 15; i++) {
            assert originalCipherText.ciphertext[paddingBlockStart + i] == padding
        }
        originalCipherText.ciphertext[paddingBlockStart + (16 - padding)] == 0

        where:
        padding << (1..15)
    }

}

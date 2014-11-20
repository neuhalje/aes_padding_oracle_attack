package name.neuhalfen.padding_oracle.oracle

import name.neuhalfen.padding_oracle.CipherText

class PaddingOracleTest extends spock.lang.Specification {
    final String AES_BLOCK = "1234567890abcdef"

    def "the oracle verifies untampered ciphertext"() {

        given:
        def sut = PaddingOracleFactory.newRandomOracle()

        when:

        def ciphertext = sut.interceptCipherText()

        then:
        sut.replayCiphertext(ciphertext) == PaddingOracle.VerificationResult.OK
    }

    def "the oracle detects tampered ciphertext"() {

        given:
        def sut = PaddingOracleFactory.newRandomOracle()

        when:

        def ciphertext = sut.interceptCipherText()
        ciphertext.ciphertext[0]++ // tamper the ciphertext

        then:
        sut.replayCiphertext(ciphertext) != PaddingOracle.VerificationResult.OK
    }


    def "toString() works"() {
        given:
        def sut = PaddingOracleFactory.newOracleWithKnownText("I am plaintext!")

        when:
        String toString = sut.toString()

        then:
        // e.g. { secretMessage:'I am plaintext!', encryptionWrapper: { algorithm:'PBKDF2WithHmacSHA1', format:'RAW', encoded:'+/EFfxS08AyOmX9gw8pRRA==' } }

        toString.contains("secretMessage:'I am plaintext!'")
        toString.contains("encryptionWrapper:")
        toString.contains("encoded:")
    }

}

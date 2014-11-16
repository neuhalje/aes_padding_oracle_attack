package name.neuhalfen.padding_oracle.oracle

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

}

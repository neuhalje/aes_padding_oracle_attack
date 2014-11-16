package name.neuhalfen.padding_oracle.oracle

import name.neuhalfen.padding_oracle.oracle.EncryptionWrapper

class EncryptionWrapperTest extends spock.lang.Specification {

    final String AES_BLOCK = "1234567890abcdef"

    def "encryption and decryption with same instance works"() {

        given:
        def sut = new EncryptionWrapper("s3cr3t".getChars())

        when:

        def encrypted = sut.encrypt("plaintext".getBytes("UTF-8"))

        def decrypted = sut.decrypt(encrypted)

        then:
        "plaintext" == new String( decrypted,"UTF-8" )
    }

    def "encryption and decryption with different instance works"() {

        given:
        def sutEnc = new EncryptionWrapper("s3cr3t".getChars())
        def sutDec = new EncryptionWrapper("s3cr3t".getChars())

        when:

        def encrypted = sutEnc.encrypt("plaintext".getBytes("UTF-8"))

        def decrypted = sutDec.decrypt(encrypted)

        then:
        "plaintext" == new String( decrypted,"UTF-8" )
    }

    def "Good signatures are verified"() {

        given:
        def sut = new EncryptionWrapper("s3cr3t".getChars())

        when:

        def encrypted = sut.encrypt("plaintext".getBytes("UTF-8"))

        then:

        sut.isSignatureCorrect("plaintext".getBytes("UTF-8"), encrypted.hmac)
    }

    def "Tampered signatures are detected"() {

        given:
        def sut = new EncryptionWrapper("s3cr3t".getChars())

        when:

        def encrypted = sut.encrypt("plaintext".getBytes("UTF-8"))

        then:

        sut.isSignatureCorrect("Xlaintext".getBytes("UTF-8"), encrypted.hmac) == false
    }


}

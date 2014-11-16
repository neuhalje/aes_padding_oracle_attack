package name.neuhalfen.padding_oracle.oracle

import spock.lang.Specification


class PaddingOracleFactoryTest extends Specification {

    def "randomString returns a string of the requested length"() {
        given:
        def requestedLen = 16

        when:
        def randomString = PaddingOracleFactory.randomString(requestedLen)

        then:
        randomString.length() == requestedLen
    }
}

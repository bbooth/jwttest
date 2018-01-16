package jwttest

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.JWSKeySelector
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import org.jasig.cas.client.validation.Assertion
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator

class JwtController {

    def index() {
        String token = params.ticket
        def data

        if (token.startsWith("ST")) {
            data = validateServiceTicket(token)
        } else {
            data = decryptToken(token)
        }

        [data: data]
    }

    private def decryptToken(String token) {
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor()
        JWKSource keySource = new RemoteJWKSet(new URL(grailsApplication.config.cas.jwksUrl))
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256

        JWSKeySelector keySelector = new JWSVerificationKeySelector(expectedJWSAlg, keySource)
        jwtProcessor.setJWSKeySelector(keySelector)

        SecurityContext ctx = null // optional context parameter, not required here
        JWTClaimsSet claimsSet = jwtProcessor.process(token, ctx)

        return claimsSet.claims
    }

    private def validateServiceTicket(String token) {
        Cas20ServiceTicketValidator validator = new Cas20ServiceTicketValidator(grailsApplication.config.cas.serverUrlPrefix)
        Assertion assertion = validator.validate(token, grailsApplication.config.cas.serviceUrl)

        return assertion?.principal?.attributes
    }
}

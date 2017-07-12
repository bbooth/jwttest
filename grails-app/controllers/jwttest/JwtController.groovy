package jwttest

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.jwk.source.ImmutableSecret
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.proc.JWEDecryptionKeySelector
import com.nimbusds.jose.proc.JWEKeySelector
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import org.jasig.cas.client.validation.Assertion
import org.jasig.cas.client.validation.Cas20ServiceTicketValidator

import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import java.text.ParseException

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
        final MACVerifier verifier = new MACVerifier(grailsApplication.config.cas.signingKey as String)
        final SecretKey decryptionKey = new SecretKeySpec(new Base64(grailsApplication.config.cas.encryptionKey as String).decode(), "AES")
        final JWKSource decryptionKeySource = new ImmutableSecret(decryptionKey)
        final JWEKeySelector encryptionKeySelector = new JWEDecryptionKeySelector(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256, decryptionKeySource)
        final ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor<>()
        jwtProcessor.setJWEKeySelector(encryptionKeySelector)

        JWTClaimsSet claimsSet = null
        try {
            SignedJWT signedJWT = SignedJWT.parse(token)
            final boolean validSignature = signedJWT.verify(verifier)
            if (validSignature) {
                Payload payload = signedJWT.getPayload()
                String encryptedToken = new Base64(payload.toString()).decodeToString()
                EncryptedJWT jwt = EncryptedJWT.parse(encryptedToken)
                claimsSet = jwtProcessor.process(jwt, null)
            }
        } catch (final KeyException e) {
            throw e
        } catch (final JOSEException | ParseException | BadJOSEException e) {
            log.debug("Exception while validating JWT token from CAS: $token", e)
        }

        return claimsSet.claims
    }

    private def validateServiceTicket(String token) {
        Cas20ServiceTicketValidator validator = new Cas20ServiceTicketValidator(grailsApplication.config.cas.serverUrlPrefix)
        Assertion assertion = validator.validate(token, "http://localhost:8080/jwt")

        return assertion?.principal?.attributes
    }
}

package com.pro.gateway.security

import io.jsonwebtoken.*
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.util.*
import javax.annotation.PostConstruct

/**
 * Created by Minky on 2022-02-08
 */

@Component
class JwtTokenProvider {
    @Value("spring.jwt.secret")
    private lateinit var secretKey: String

    @PostConstruct
    private fun init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.toByteArray())
    }

    fun getUserUuid(token: String): String {
        return Jwts.parser().setSigningKey(secretKey)
            .parseClaimsJws(token).body.subject
    }

    fun getUserRole(token: String): String {
        return Jwts.parser().setSigningKey(secretKey)
            .parseClaimsJws(token).body["role"].toString()
    }

    fun validateToken(token: String): Boolean {
        try {
            Jwts.parser().setSigningKey(secretKey)
                .parseClaimsJws(token)
            return true
        } catch (e: SecurityException) {
        } catch (e: MalformedJwtException) {
        } catch (e: ExpiredJwtException) {
        } catch (e: UnsupportedJwtException) {
        } catch (e: IllegalArgumentException) {
        }
        return false
    }
}
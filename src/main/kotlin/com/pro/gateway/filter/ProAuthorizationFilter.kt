package com.pro.gateway.filter

import com.pro.gateway.security.JwtTokenProvider
import com.pro.gateway.security.SecurityHeader
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.cloud.gateway.filter.GatewayFilter
import org.springframework.cloud.gateway.filter.GatewayFilterChain
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.server.ServerWebExchange
import reactor.core.publisher.Mono
import java.util.*
import java.util.function.Consumer

/**
 * Created by Minky on 2022-02-10
 */

@Component
class ProAuthorizationFilter: AbstractGatewayFilterFactory<ProAuthorizationFilter.Config>(Config::class.java) {
    @Autowired
    private lateinit var jwtTokenProvider: JwtTokenProvider

    override fun apply(config: Config): GatewayFilter {
        return (GatewayFilter { exchange: ServerWebExchange, chain: GatewayFilterChain ->
            val request = exchange.request

            if (!request.headers.containsKey(SecurityHeader.X_AUTH_TOKEN)) {
                return@GatewayFilter handleUnAuthorized(exchange)
            }

            val accessTokens = request.headers[SecurityHeader.X_AUTH_TOKEN] as List<String>
            val accessToken = Objects.requireNonNull(accessTokens)[0]

            if (!jwtTokenProvider.validateToken(accessToken)) {
                return@GatewayFilter handleUnAuthorized(exchange)
            }

            val uuid = jwtTokenProvider.getUserUuid(accessToken)
            val userRole = jwtTokenProvider.getUserRole(accessToken)

            if (userRole != "PRO") {
                return@GatewayFilter handleUnAuthorized(exchange)
            }

            val httpHeaders =
                Consumer<HttpHeaders> { httpHeader -> httpHeader.set(SecurityHeader.UUID, uuid) }

            val serverHttpRequest = exchange.request.mutate().headers(httpHeaders).build()
            exchange.mutate().request(serverHttpRequest).build()

            return@GatewayFilter chain.filter(exchange.mutate().request(request).build())

        })
    }

    private fun handleUnAuthorized(exchange: ServerWebExchange): Mono<Void> {
        val response = exchange.response
        response.statusCode = HttpStatus.UNAUTHORIZED
        return response.setComplete()
    }

    class Config
}
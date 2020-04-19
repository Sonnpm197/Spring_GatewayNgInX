package com.son.gateway.filters;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public class CustomFilter extends AbstractGatewayFilterFactory<CustomFilter.Config> {
    @Override
    public GatewayFilter apply(Config config) {
        return (ServerWebExchange exchange, GatewayFilterChain chain) -> {
            ServerHttpRequest request = exchange.getRequest();

                return chain.filter(exchange);

            // check header contains Bearer token or not
            String bearToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (!StringUtils.hasText(bearToken) || !bearToken.startsWith(GatewayConstant.BEARER_TOKEN)) {
                return unauthorized(exchange, HttpStatus.UNAUTHORIZED);
            }
            // validate token
            String jwtToken = bearToken.substring(GatewayConstant.BEARER_TOKEN.length());
            String tokenSubject = jwtTokenProvider.validateToken(jwtToken);
            if (null == tokenSubject) {
                return unauthorized(exchange, HttpStatus.UNAUTHORIZED);
            }
            //
            String method = request.getMethodValue();
            log.debug("url: {}, method: {}, headers: {}", url, method, request.getHeaders());
            // parse token to get user id or ger direct from authentication server

            if (authService.hasPermission("pw-user", url, method)) {
                ServerHttpRequest modifiedRequest = request.mutate()
                        .header("X-Parkway-Token", "Bearer " + jwtToken)
                        .build();
                return chain.filter(exchange.mutate().request(modifiedRequest).build());
            }
            return unauthorized(exchange, HttpStatus.UNAUTHORIZED);
        };
    }

    private Mono<Void> unauthorized(ServerWebExchange serverWebExchange, HttpStatus httpStatus) {
        serverWebExchange
                .getResponse()
                .setStatusCode(httpStatus);
        DataBuffer buffer = serverWebExchange
                .getResponse()
                .bufferFactory()
                .wrap(HttpStatus.UNAUTHORIZED.getReasonPhrase().getBytes());
        return serverWebExchange.getResponse().writeWith(Flux.just(buffer));
    }

    public class Config {
    }
}

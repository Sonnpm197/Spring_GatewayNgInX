package com.son.gateway.filters;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.impl.TextCodec;
import lombok.NoArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Component
public class CustomFilter extends AbstractGatewayFilterFactory<CustomFilter.Config> {

    public CustomFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (ServerWebExchange exchange, GatewayFilterChain chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String url = request.getPath().value();

            // Allow urls to go through
            List<String> whiteListUrls = new ArrayList<>();
            if (whiteListUrls.contains(url)) {
                return chain.filter(exchange);
            }

            // check header contains Bearer token or not
            String bearerToken = request.getHeaders().getFirst("Authorization");
            if (!StringUtils.hasText(bearerToken) || !bearerToken.startsWith("Bearer ")) {
                return unauthorized(exchange, HttpStatus.UNAUTHORIZED);
            }

            // validate token
            String jwtToken = bearerToken.substring("Bearer ".length());
            if (!validateToken(jwtToken)) {
                return unauthorized(exchange, HttpStatus.UNAUTHORIZED);
            }

            String method = request.getMethodValue();

            if (checkPermission()) {
                ServerHttpRequest modifiedRequest = request.mutate()
//                        .header("Authorization", "Bearer " + jwtToken)
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

    public static class Config {
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(Base64.getEncoder().encodeToString("secret-key".getBytes()))
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private boolean checkPermission() {
        return true;
    }
}

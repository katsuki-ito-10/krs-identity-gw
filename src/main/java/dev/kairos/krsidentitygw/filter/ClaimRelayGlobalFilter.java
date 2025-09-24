package dev.kairos.krsidentitygw.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Order(-101) // 認証フィルタより前に実行（AUTHENTICATION_ORDER=-100 の1つ前）
public class ClaimRelayGlobalFilter implements GlobalFilter {

  private final String internalSecret;
  private final ReactiveJwtDecoder jwtDecoder;

  public ClaimRelayGlobalFilter(
      @Value("${internal.auth.secret}") String internalSecret,
      ReactiveJwtDecoder jwtDecoder
  ) {
    this.internalSecret = internalSecret;
    this.jwtDecoder = jwtDecoder;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    if (auth == null || !auth.startsWith("Bearer ")) {
      // 未ログインなどはそのまま（最終的に Security が 401/403）
      return chain.filter(exchange);
    }

    String token = auth.substring(7);

    return jwtDecoder.decode(token)
        .map(jwt -> mutateWithInternalHeaders(exchange, jwt))
        // 不正JWTはここでは処理せず、標準Securityに任せる
        .onErrorResume(JwtException.class, e -> Mono.just(exchange))
        .flatMap(chain::filter);
  }

  private ServerWebExchange mutateWithInternalHeaders(ServerWebExchange exchange, Jwt jwt) {
    String sub   = jwt.getSubject();
    String email = jwt.getClaimAsString("email");
    String name  = firstNonNull(jwt.getClaimAsString("preferred_username"),
                                jwt.getClaimAsString("name"));

    // Authorization は残す（この後 Security が検証する）
    ServerHttpRequest mutated = exchange.getRequest().mutate()
        .headers(h -> {
          h.set("X-Internal-Auth", internalSecret);
          if (sub != null)   h.set("X-User-Id", sub);
          if (email != null) h.set("X-User-Email", email);
          if (name != null)  h.set("X-User-Name", name);
        })
        .build();

    return exchange.mutate().request(mutated).build();
  }

  private static String firstNonNull(String a, String b) {
    return a != null ? a : b;
  }
}
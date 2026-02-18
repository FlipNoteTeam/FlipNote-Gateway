package flipnote.apigateway.client;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Component
public class TokenValidationClient {

    private final WebClient webClient;

    public TokenValidationClient(@Value("${app.user-service.url}") String userServiceUrl) {
        this.webClient = WebClient.builder()
                .baseUrl(userServiceUrl)
                .build();
    }

    public Mono<TokenValidationResponse> validateToken(String token) {
        return webClient.post()
                .uri("/v1/auth/token/validate")
                .bodyValue(new TokenValidationRequest(token))
                .retrieve()
                .bodyToMono(TokenValidationResponse.class);
    }

    public record TokenValidationRequest(String token) {}

    public record TokenValidationResponse(Long userId, String email, String role) {}
}

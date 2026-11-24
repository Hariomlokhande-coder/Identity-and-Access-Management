package com.iamplatform.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.iamplatform.auth.dto.TokenResponse;
import com.iamplatform.support.IntegrationTestBase;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * The hardest case in the design: two refreshes of the same token arriving together.
 *
 * <p>Correctness rests on a single conditional UPDATE in the database, so it can only
 * be tested against a real database with real concurrent requests.
 */
class RefreshRotationConcurrencyIT extends IntegrationTestBase {

    private static final int CONCURRENT_REQUESTS = 8;

    @Test
    @DisplayName("only one of many simultaneous refreshes succeeds, and the rest are refused")
    void exactlyOneConcurrentRefreshWins() throws Exception {
        String email = uniqueEmail("race");
        registerAndVerify(email);
        TokenResponse tokens = login(email);

        List<ResponseEntity<TokenResponse>> responses = fireSimultaneously(tokens.refreshToken());

        long succeeded = responses.stream().filter(r -> r.getStatusCode() == HttpStatus.OK).count();
        long refused = responses.stream().filter(r -> r.getStatusCode() == HttpStatus.UNAUTHORIZED).count();

        assertThat(succeeded)
                .withFailMessage("expected exactly one winner, got %d", succeeded)
                .isEqualTo(1);
        assertThat(refused).isEqualTo(CONCURRENT_REQUESTS - 1);
    }

    /**
     * Losing the race is indistinguishable from a genuine replay, so the platform takes
     * the safe reading: the family is compromised and the session ends. The winner
     * therefore also loses its brand new token.
     */
    @Test
    @DisplayName("a concurrent double refresh is treated as reuse and ends the session")
    void concurrentRefreshRevokesTheWholeFamily() throws Exception {
        String email = uniqueEmail("family");
        registerAndVerify(email);
        TokenResponse tokens = login(email);

        List<ResponseEntity<TokenResponse>> responses = fireSimultaneously(tokens.refreshToken());
        TokenResponse winner = responses.stream()
                .filter(r -> r.getStatusCode() == HttpStatus.OK)
                .findFirst()
                .orElseThrow()
                .getBody();

        ResponseEntity<Map> afterReuse = post("/auth/refresh", Map.of("refreshToken", winner.refreshToken()));
        assertThat(afterReuse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        assertThat(authorized("/users/me", HttpMethod.GET, winner.accessToken(), null, Map.class).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    @DisplayName("sequentially replaying a rotated token is refused")
    void replayOfRotatedTokenIsRefused() {
        String email = uniqueEmail("replay");
        registerAndVerify(email);
        TokenResponse tokens = login(email);

        assertThat(post("/auth/refresh", Map.of("refreshToken", tokens.refreshToken()), TokenResponse.class)
                .getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(post("/auth/refresh", Map.of("refreshToken", tokens.refreshToken()), TokenResponse.class)
                .getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private List<ResponseEntity<TokenResponse>> fireSimultaneously(String refreshToken) throws Exception {
        // A barrier makes the requests overlap in the database rather than merely being
        // submitted at nearly the same time.
        CyclicBarrier barrier = new CyclicBarrier(CONCURRENT_REQUESTS);
        try (ExecutorService executor = Executors.newFixedThreadPool(CONCURRENT_REQUESTS)) {
            List<Callable<ResponseEntity<TokenResponse>>> calls = java.util.stream.IntStream
                    .range(0, CONCURRENT_REQUESTS)
                    .<Callable<ResponseEntity<TokenResponse>>>mapToObj(i -> () -> {
                        barrier.await();
                        return post("/auth/refresh", Map.of("refreshToken", refreshToken), TokenResponse.class);
                    })
                    .toList();

            List<Future<ResponseEntity<TokenResponse>>> futures = executor.invokeAll(calls);
            return futures.stream().map(future -> {
                try {
                    return future.get();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }).toList();
        }
    }
}

package dev.buzzverse.buzzcore.client;

import dev.buzzverse.buzzcore.model.github.Team;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;

@Component
public class GitHubClient {

    private static final String GITHUB_URL = "https://api.github.com";

    private RestClient getRestClient() {
        return RestClient.builder()
                .baseUrl(GITHUB_URL)
                .build();
    }

    public List<Team> fetchUserTeams(String accessToken) {
        return getRestClient()
                .get()
                .uri("/user/teams")
                .headers(headers -> headers.setBearerAuth(accessToken))
                .retrieve()
                .body(new ParameterizedTypeReference<>() {});
    }

}

package dev.buzzverse.buzzcore.service;

import dev.buzzverse.buzzcore.client.GitHubClient;
import dev.buzzverse.buzzcore.model.github.Organization;
import dev.buzzverse.buzzcore.model.github.Team;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class GitHubOAuth2UserService extends DefaultOAuth2UserService {

    private final GitHubClient gitHubClient;

    @Value("${github.organization}")
    private String requiredOrg;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauthUser = super.loadUser(userRequest);

        Set<GrantedAuthority> mapped = new HashSet<>(oauthUser.getAuthorities());

        List<Team> teams = gitHubClient.fetchUserTeams(userRequest.getAccessToken().getTokenValue());

        for (Team team : teams) {
            Organization org = team.organization();
            String orgLogin = org.login();
            if (!requiredOrg.isEmpty() && !requiredOrg.equals(orgLogin)) {
                continue;
            }

            String slug = team.slug();
            mapped.add(new SimpleGrantedAuthority("ROLE_" + slug.toUpperCase()));
        }

        return new DefaultOAuth2User(mapped, oauthUser.getAttributes(), "email");
    }

}

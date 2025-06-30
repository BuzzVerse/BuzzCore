package dev.buzzverse.buzzcore.utils;

import dev.buzzverse.buzzcore.security.CurrentUser;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class AuthFacade {

    public CurrentUser requireCurrentUser() {
        return currentUser()
                .orElseThrow(() -> new IllegalStateException("No authenticated user found"));
    }

    public Optional<CurrentUser> currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated()) {
            return Optional.empty();
        }

        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            return Optional.of(fromJwt(jwtAuth));
        }

        if (auth instanceof OAuth2AuthenticationToken oauth) {
            return Optional.of(fromOAuth2(oauth));
        }

        if (auth.getPrincipal() instanceof UserDetails userDetails) {
            return Optional.of(fromUserDetails(userDetails, auth));
        }

        return Optional.of(fromGeneric(auth));
    }


    private CurrentUser fromJwt(JwtAuthenticationToken jwtAuth) {
        Jwt jwt = jwtAuth.getToken();
        Map<String, Object> claims = jwt.getClaims();

        return new CurrentUser(
                (String) claims.getOrDefault("preferred_username", jwt.getSubject()),
                (String) claims.get("email"),
                "jwt",
                extractRoles(jwtAuth.getAuthorities())
        );
    }

    private CurrentUser fromOAuth2(OAuth2AuthenticationToken oauth) {
        OAuth2User user = oauth.getPrincipal();

        return new CurrentUser(
                user.getAttribute("login") != null
                        ? user.getAttribute("login")
                        : user.getAttribute("name"),
                user.getAttribute("email"),
                oauth.getAuthorizedClientRegistrationId(),
                extractRoles(oauth.getAuthorities())
        );
    }

    private CurrentUser fromUserDetails(UserDetails user, Authentication auth) {
        return new CurrentUser(
                user.getUsername(),
                user.getUsername(),
                "local",
                extractRoles(auth.getAuthorities())
        );
    }

    private CurrentUser fromGeneric(Authentication auth) {
        return new CurrentUser(
                auth.getName(),
                auth.getName(),
                "generic",
                extractRoles(auth.getAuthorities())
        );
    }

    private List<String> extractRoles(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
    }

}

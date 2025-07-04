package dev.buzzverse.buzzcore.utils;

import dev.buzzverse.buzzcore.model.dto.CurrentUser;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
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

        return Optional.of(switch (auth) {
            case JwtAuthenticationToken jwtAuth -> fromJwt(jwtAuth);
            case OAuth2AuthenticationToken oauth -> fromOAuth2(oauth);
            default -> fromGeneric(auth);
        });
    }

    private CurrentUser fromJwt(JwtAuthenticationToken jwtAuth) {
        Jwt jwt = jwtAuth.getToken();
        return new CurrentUser(
                StringUtils.firstNonBlank(jwt.getClaimAsString("login"), jwt.getSubject()),
                jwt.getClaimAsString("email"),
                jwt.getClaimAsString("provider"),
                safeRoles(jwtAuth.getAuthorities())
        );
    }

    private CurrentUser fromOAuth2(OAuth2AuthenticationToken oauth) {
        OAuth2User user = oauth.getPrincipal();

        String login = user.getAttribute("login");
        String name = user.getAttribute("name");
        String email = user.getAttribute("email");

        return new CurrentUser(
                StringUtils.firstNonBlank(login, name, oauth.getName()),
                email,
                oauth.getAuthorizedClientRegistrationId(),
                safeRoles(oauth.getAuthorities())
        );
    }

    private CurrentUser fromGeneric(Authentication auth) {
        return new CurrentUser(
                auth.getName(),
                auth.getName(),
                "generic",
                safeRoles(auth.getAuthorities())
        );
    }

    private static List<String> safeRoles(Collection<? extends GrantedAuthority> auths) {
        return List.copyOf(auths == null ? List.of() : auths.stream()
                .map(GrantedAuthority::getAuthority)
                .toList());
    }

}

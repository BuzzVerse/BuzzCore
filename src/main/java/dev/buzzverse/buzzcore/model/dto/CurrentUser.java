package dev.buzzverse.buzzcore.model.dto;

import java.util.Collection;

public record CurrentUser(
        String username,
        String email,
        String provider,
        Collection<String> roles
) {}

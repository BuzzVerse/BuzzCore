package dev.buzzverse.buzzcore.controller;

import dev.buzzverse.buzzcore.model.dto.CurrentUser;
import dev.buzzverse.buzzcore.utils.CurrentUserPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MeController {

    @GetMapping("/me")
    public CurrentUser me(@CurrentUserPrincipal CurrentUser user) {
        return user;
    }

}

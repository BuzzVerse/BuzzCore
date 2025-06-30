package dev.buzzverse.buzzcore.controller;

import dev.buzzverse.buzzcore.model.github.DeviceGrant;
import dev.buzzverse.buzzcore.service.DeviceGrantStore;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

@Controller
@RequiredArgsConstructor
public class VerificationController {

    private final DeviceGrantStore store;

    @GetMapping("/cli/verify")
    public String verify(@RequestParam("user_code") String userCode, HttpSession session) {
        DeviceGrant grant = store.byUser(userCode)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        session.setAttribute("device_code", grant.deviceCode());
        return "redirect:/oauth2/authorization/github";
    }

}

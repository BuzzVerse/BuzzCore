package dev.buzzverse.buzzcore.controller;

import dev.buzzverse.buzzcore.model.ChirpStackEvent;
import dev.buzzverse.buzzcore.service.ChirpStackEventService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/events")
@RequiredArgsConstructor
class ChirpStackEventController {

    private final ChirpStackEventService chirpStackEventService;

    @PostMapping(consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public void handleEvent(@RequestParam ChirpStackEvent event, @RequestBody byte[] requestBody) {
        chirpStackEventService.handleEvent(event, requestBody);
    }
}

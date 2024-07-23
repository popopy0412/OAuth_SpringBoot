package com.example.oauth.controller;

import com.example.oauth.service.OAuthService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/oauth2")
public class OAuthController {

    private static final Logger log = LoggerFactory.getLogger(OAuthController.class);
    private final OAuthService oAuthService;

    @GetMapping("/callback/{registrationId}")
    public ResponseEntity<String> callback(@RequestParam("code") String code, @PathVariable("registrationId") String registrationId) {
        log.info(registrationId);
        return oAuthService.processCallback(code, registrationId);
    }

    @GetMapping("/login")
    public void login(@RequestParam("registrationId") String registrationId, HttpServletResponse response) throws IOException {
        String authorizationUri = oAuthService.getAuthorizationUri(registrationId);
        log.info("Redirecting to: " + authorizationUri);
        response.sendRedirect(authorizationUri);
    }
}

package com.example.oauth.service;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class OAuthService {

    private static final Logger log = LoggerFactory.getLogger(OAuthService.class);

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${oauth2.google.client-id}")
    private String googleClientId;

    @Value("${oauth2.google.client-secret}")
    private String googleClientSecret;

    @Value("${oauth2.google.redirect-uri}")
    private String googleRedirectUri;

    @Value("${oauth2.google.token-uri}")
    private String googleTokenUri;

    @Value("${oauth2.google.user-info-uri}")
    private String googleUserInfoUri;

    @Value("${oauth2.google.authorization-uri}")
    private String googleAuthorizationUri;

    @Value("${oauth2.kakao.client-id}")
    private String kakaoClientId;

    @Value("${oauth2.kakao.client-secret}")
    private String kakaoClientSecret;

    @Value("${oauth2.kakao.redirect-uri}")
    private String kakaoRedirectUri;

    @Value("${oauth2.kakao.token-uri}")
    private String kakaoTokenUri;

    @Value("${oauth2.kakao.user-info-uri}")
    private String kakaoUserInfoUri;

    @Value("${oauth2.kakao.authorization-uri}")
    private String kakaoAuthorizationUri;

    @Value("${oauth2.apple.client-id}")
    private String appleClientId;

    @Value("${oauth2.apple.client-secret}")
    private String appleClientSecret;

    @Value("${oauth2.apple.redirect-uri}")
    private String appleRedirectUri;

    @Value("${oauth2.apple.token-uri}")
    private String appleTokenUri;

    @Value("${oauth2.apple.user-info-uri}")
    private String appleUserInfoUri;

    @Value("${oauth2.apple.authorization-uri}")
    private String appleAuthorizationUri;

    public ResponseEntity<String> processCallback(String code, String registrationId) {
        try {
            String clientId;
            String clientSecret;
            String redirectUri;
            String tokenUri;
            String userInfoUri;

            switch (registrationId) {
                case "google":
                    clientId = googleClientId;
                    clientSecret = googleClientSecret;
                    redirectUri = googleRedirectUri;
                    tokenUri = googleTokenUri;
                    userInfoUri = googleUserInfoUri;
                    break;
                case "kakao":
                    clientId = kakaoClientId;
                    clientSecret = kakaoClientSecret;
                    redirectUri = kakaoRedirectUri;
                    tokenUri = kakaoTokenUri;
                    userInfoUri = kakaoUserInfoUri;
                    break;
                case "apple":
                    clientId = appleClientId;
                    clientSecret = appleClientSecret;
                    redirectUri = appleRedirectUri;
                    tokenUri = appleTokenUri;
                    userInfoUri = appleUserInfoUri;
                    break;
                default:
                    throw new IllegalArgumentException("Unsupported registration id: " + registrationId);
            }

            // 액세스 토큰 요청
            Map<String, String> tokenRequest = new HashMap<>();
            tokenRequest.put("code", code);
            tokenRequest.put("client_id", clientId);
            tokenRequest.put("client_secret", clientSecret);
            tokenRequest.put("redirect_uri", redirectUri);
            tokenRequest.put("grant_type", "authorization_code");

            log.info("Callback with code: " + code);

            ResponseEntity<JsonNode> tokenResponse = restTemplate.postForEntity(tokenUri, tokenRequest, JsonNode.class);

            if (tokenResponse.getStatusCode().is2xxSuccessful()) {
                log.info("Token successfully expired");
                log.info("Token: " + tokenResponse.getBody());
                String accessToken = Objects.requireNonNull(tokenResponse.getBody()).get("access_token").asText();
                String refreshToken = tokenResponse.getBody().get("refresh_token").asText();
                log.info("Refresh token: " + refreshToken);
                log.info("Access token: " + accessToken);

                // 사용자 정보 요청
                ResponseEntity<String> userInfoResponse = restTemplate.getForEntity(userInfoUri + "?access_token=" + accessToken, String.class);

                log.info("User info: " + userInfoResponse.getBody());

                String redirectUrl = "flutteroauth://callback?access_token=" + accessToken + "&refresh_token=" + refreshToken;
                return ResponseEntity.status(302).header("Location", redirectUrl).build();
            } else {
                log.error("Failed to retrieve access token: " + tokenResponse.getStatusCode());
                return ResponseEntity.status(tokenResponse.getStatusCode()).body("Failed to retrieve access token");
            }
        } catch (Exception e) {
            log.error("Exception occurred during OAuth callback processing", e);
            return ResponseEntity.status(500).body("Internal Server Error: " + e.getMessage());
        }
    }

    public String getAuthorizationUri(String registrationId) {
        String clientId;
        String redirectUri;
        String authorizationUri;

        switch (registrationId) {
            case "google":
                clientId = googleClientId;
                redirectUri = googleRedirectUri;
                authorizationUri = googleAuthorizationUri;
                break;
            case "kakao":
                clientId = kakaoClientId;
                redirectUri = kakaoRedirectUri;
                authorizationUri = kakaoAuthorizationUri;
                break;
            case "apple":
                clientId = appleClientId;
                redirectUri = appleRedirectUri;
                authorizationUri = appleAuthorizationUri;
                break;
            default:
                throw new IllegalArgumentException("Unsupported registration id: " + registrationId);
        }

        return authorizationUri
                + "?client_id=" + clientId
                + "&redirect_uri=" + redirectUri
                + "&response_type=code"
                + "&scope=profile email"
                + "&access_type=offline"
                + "&prompt=consent";
    }
}

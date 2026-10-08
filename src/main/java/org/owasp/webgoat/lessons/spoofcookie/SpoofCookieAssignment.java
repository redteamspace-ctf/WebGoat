/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.UnsatisfiedServletRequestParameterException;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The authentication cookie is an opaque, randomly generated session token. It carries no
 * information about the user, the user is looked up server-side, so the cookie cannot be
 * decoded, modified or forged to impersonate somebody else.
 *
 * @author OWASP
 */
@AssignmentHints({"spoofcookie.hint1", "spoofcookie.hint2", "spoofcookie.hint3"})
@RestController
public class SpoofCookieAssignment implements AssignmentEndpoint {

  private static final String COOKIE_NAME = "spoof_auth";
  private static final String COOKIE_INFO =
      "Cookie details for user %s:<br />" + COOKIE_NAME + "=%s";
  private static final String ATTACK_USERNAME = "tom";
  private static final Duration TOKEN_LIFETIME = Duration.ofMinutes(30);
  private static final Map<String, String> users =
      Map.of("webgoat", "webgoat", "admin", "admin", ATTACK_USERNAME, "apasswordfortom");

  private record IssuedToken(String username, Instant expiresAt) {}

  private final SecureRandom secureRandom = new SecureRandom();
  private final Map<String, IssuedToken> issuedTokens = new ConcurrentHashMap<>();

  @PostMapping(path = "/SpoofCookie/login")
  @ResponseBody
  @ExceptionHandler(UnsatisfiedServletRequestParameterException.class)
  public AttackResult login(
      @RequestParam String username,
      @RequestParam String password,
      @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
      HttpServletResponse response) {

    if (StringUtils.isEmpty(cookieValue)) {
      return credentialsLoginFlow(username, password, response);
    } else {
      return cookieLoginFlow(cookieValue);
    }
  }

  @GetMapping(path = "/SpoofCookie/cleanup")
  public void cleanup(
      @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
      HttpServletResponse response) {
    if (cookieValue != null) {
      issuedTokens.remove(cookieValue);
    }
    Cookie cookie = new Cookie(COOKIE_NAME, "");
    cookie.setMaxAge(0);
    cookie.setPath("/WebGoat");
    response.addCookie(cookie);
  }

  private AttackResult credentialsLoginFlow(
      String username, String password, HttpServletResponse response) {
    String lowerCasedUsername = username.toLowerCase();
    if (ATTACK_USERNAME.equals(lowerCasedUsername)
        && users.get(lowerCasedUsername).equals(password)) {
      return informationMessage(this).feedback("spoofcookie.cheating").build();
    }

    String authPassword = users.getOrDefault(lowerCasedUsername, "");
    if (!authPassword.isBlank() && authPassword.equals(password)) {
      String newCookieValue = issueToken(lowerCasedUsername);
      Cookie newCookie = new Cookie(COOKIE_NAME, newCookieValue);
      newCookie.setPath("/WebGoat");
      newCookie.setSecure(true);
      newCookie.setHttpOnly(true);
      newCookie.setMaxAge((int) TOKEN_LIFETIME.toSeconds());
      response.addCookie(newCookie);
      return informationMessage(this)
          .feedback("spoofcookie.login")
          .output(String.format(COOKIE_INFO, lowerCasedUsername, newCookie.getValue()))
          .build();
    }

    return informationMessage(this).feedback("spoofcookie.wrong-login").build();
  }

  private AttackResult cookieLoginFlow(String cookieValue) {
    IssuedToken token = issuedTokens.get(cookieValue);
    if (token == null || Instant.now().isAfter(token.expiresAt())) {
      issuedTokens.remove(cookieValue);
      return failed(this).feedback("spoofcookie.wrong-cookie").build();
    }

    String cookieUsername = token.username();
    if (users.containsKey(cookieUsername)) {
      if (cookieUsername.equals(ATTACK_USERNAME)) {
        return success(this).build();
      }
      return failed(this)
          .feedback("spoofcookie.cookie-login")
          .output(String.format(COOKIE_INFO, cookieUsername, cookieValue))
          .build();
    }

    return failed(this).feedback("spoofcookie.wrong-cookie").build();
  }

  private String issueToken(String username) {
    Instant now = Instant.now();
    issuedTokens.entrySet().removeIf(entry -> now.isAfter(entry.getValue().expiresAt()));
    byte[] bytes = new byte[32];
    secureRandom.nextBytes(bytes);
    String token = Base64.getEncoder().encodeToString(bytes);
    issuedTokens.put(token, new IssuedToken(username, now.plus(TOKEN_LIFETIME)));
    return token;
  }
}

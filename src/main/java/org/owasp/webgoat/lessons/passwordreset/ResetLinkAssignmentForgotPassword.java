/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import jakarta.servlet.http.HttpServletRequest;
import java.util.UUID;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * Creates password reset links. The link that is mailed is always built from the application's
 * configured address, never from the request's Host header, and the link is registered for the
 * account it was requested for so that only that account can use it.
 */
@RestController
public class ResetLinkAssignmentForgotPassword implements AssignmentEndpoint {

  private final RestTemplate restTemplate;
  private final String webWolfHost;
  private final String webWolfPort;
  private final String webWolfURL;
  private final String webWolfMailURL;
  private final String trustedBaseUrl;

  public ResetLinkAssignmentForgotPassword(
      RestTemplate restTemplate,
      @Value("${webwolf.host}") String webWolfHost,
      @Value("${webwolf.port}") String webWolfPort,
      @Value("${webwolf.url}") String webWolfURL,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.url}") String webGoatUrl) {
    this.restTemplate = restTemplate;
    this.webWolfHost = webWolfHost;
    this.webWolfPort = webWolfPort;
    this.webWolfURL = webWolfURL;
    this.webWolfMailURL = webWolfMailURL;
    this.trustedBaseUrl = webGoatUrl;
  }

  @PostMapping("/PasswordReset/ForgotPassword/create-password-reset-link")
  @ResponseBody
  public AttackResult sendPasswordResetLink(
      @RequestParam String email, HttpServletRequest request, @CurrentUsername String username) {
    if (email == null || !email.matches("[^@\\s]+@[^@\\s]+")) {
      return failed(this).output("Please provide a valid e-mail address").build();
    }
    String resetLink = UUID.randomUUID().toString();
    ResetLinkAssignment.registerResetLink(resetLink, email);

    String host = request.getHeader(HttpHeaders.HOST);
    boolean poisonedHost =
        host != null && host.contains(webWolfPort) && host.contains(webWolfHost);
    if (ResetLinkAssignment.TOM_EMAIL.equals(email) && poisonedHost) {
      // Simulates the victim following the link in a phishing style e-mail. The link is bound
      // to Tom's account, so whoever captures it cannot use it to change Tom's password.
      simulateVictimClick(webWolfURL, resetLink);
    } else {
      try {
        sendMailToUser(email, resetLink);
      } catch (Exception e) {
        return failed(this).output("E-mail can't be send. please try again.").build();
      }
    }

    // sending a reset e-mail is a neutral action, it never completes the assignment
    return informationMessage(this).feedback("email.send").feedbackArgs(email).build();
  }

  private void sendMailToUser(String email, String resetLink) {
    int index = email.indexOf("@");
    String username = email.substring(0, index == -1 ? email.length() : index);
    PasswordResetEmail mail =
        PasswordResetEmail.builder()
            .title("Your password reset link")
            // the link is built from the configured application address, not the Host header
            .contents(String.format(ResetLinkAssignment.TEMPLATE, trustedBaseUrl, resetLink))
            .sender("password-reset@webgoat-cloud.net")
            .recipient(username)
            .build();
    this.restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
  }

  private void simulateVictimClick(String webWolfURL, String resetLink) {
    try {
      HttpHeaders httpHeaders = new HttpHeaders();
      HttpEntity httpEntity = new HttpEntity(httpHeaders);
      new RestTemplate()
          .exchange(
              String.format("%s/PasswordReset/reset/reset-password/%s", webWolfURL, resetLink),
              HttpMethod.GET,
              httpEntity,
              Void.class);
    } catch (Exception e) {
      // best effort simulation
    }
  }
}

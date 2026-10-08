/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-login-hint1", "csrf-login-hint2", "csrf-login-hint3"})
public class CSRFLogin implements AssignmentEndpoint {

  @PostMapping(
      path = "/csrf/login",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(
      @CurrentUsername String username, jakarta.servlet.http.HttpServletRequest request) {
    // Security fix: reject cross-site (forged) logins. Require a same-origin Referer header.
    String referer = request.getHeader("Referer");
    String host = request.getHeader("Host");
    boolean sameOrigin = referer != null && host != null && referer.contains(host);
    if (!sameOrigin) {
      return failed(this).feedback("csrf-login-failed").feedbackArgs(username).build();
    }
    return failed(this).feedback("csrf-login-failed").feedbackArgs(username).build();
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.logging;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.apache.logging.log4j.util.Strings;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogSpoofingTask implements AssignmentEndpoint {

  @PostMapping("/LogSpoofing/log-spoofing")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    if (Strings.isEmpty(username)) {
      return failed(this).output(username).build();
    }
    // Security fix: strip line breaks and encode HTML so a user-supplied value can never
    // forge additional log entries.
    String sanitized =
        org.springframework.web.util.HtmlUtils.htmlEscape(
            username.replaceAll("[\\r\\n]", "_"));
    return failed(this).output("Login failed for username: " + sanitized).build();
  }
}

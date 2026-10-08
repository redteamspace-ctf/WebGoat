/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.authbypass;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by jason on 1/5/17.
 */
@RestController
@AssignmentHints({
  "auth-bypass.hints.verify.1",
  "auth-bypass.hints.verify.2",
  "auth-bypass.hints.verify.3",
  "auth-bypass.hints.verify.4"
})
public class VerifyAccount implements AssignmentEndpoint {

  private static final List<String> REQUIRED_QUESTIONS = List.of("secQuestion0", "secQuestion1");

  private final LessonSession userSessionData;

  public VerifyAccount(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @PostMapping(
      path = "/auth-bypass/verify-account",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult completed(
      @RequestParam String userId, @RequestParam String verifyMethod, HttpServletRequest req)
      throws ServletException, IOException {
    AccountVerificationHelper verificationHelper = new AccountVerificationHelper();
    HashMap<String, String> submittedAnswers = parseSecQuestions(req);

    // Only the registered security questions are accepted; any other or missing parameter
    // means the verification cannot be performed at all.
    if (!submittedAnswers.keySet().containsAll(REQUIRED_QUESTIONS)
        || submittedAnswers.size() != REQUIRED_QUESTIONS.size()) {
      return failed(this).feedback("verify-account.failed").build();
    }

    Integer accountId;
    try {
      accountId = Integer.valueOf(userId);
    } catch (NumberFormatException e) {
      return failed(this).feedback("verify-account.failed").build();
    }

    if (verificationHelper.didUserLikelylCheat(submittedAnswers)) {
      return failed(this)
          .feedback("verify-account.cheated")
          .output("Yes, you guessed correctly, but see the feedback message")
          .build();
    }

    if (verificationHelper.verifyAccount(accountId, submittedAnswers)) {
      userSessionData.setValue("account-verified-id", userId);
      return success(this).feedback("verify-account.success").build();
    } else {
      return failed(this).feedback("verify-account.failed").build();
    }
  }

  private HashMap<String, String> parseSecQuestions(HttpServletRequest req) {
    HashMap<String, String> userAnswers = new HashMap<>();
    List<String> paramNames = Collections.list(req.getParameterNames());
    for (String paramName : paramNames) {
      if (REQUIRED_QUESTIONS.contains(paramName)) {
        userAnswers.put(paramName, req.getParameter(paramName));
      } else if (paramName.contains("secQuestion")) {
        // remember that an unknown question was submitted so the size check fails
        userAnswers.put(paramName, req.getParameter(paramName));
      }
    }
    return userAnswers;
  }
}

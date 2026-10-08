/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.passwordreset;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import static org.springframework.util.StringUtils.hasText;

import com.google.common.collect.Maps;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.passwordreset.resetlink.PasswordChangeForm;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

/**
 * Password reset links are random, short lived, single use and bound to the account they were
 * requested for: a link can only change the password of the account that owns it, so a link
 * obtained by somebody else (for example through a poisoned e-mail) cannot be used to take over
 * that account.
 */
@RestController
@AssignmentHints({
  "password-reset-hint1",
  "password-reset-hint2",
  "password-reset-hint3",
  "password-reset-hint4",
  "password-reset-hint5",
  "password-reset-hint6"
})
public class ResetLinkAssignment implements AssignmentEndpoint {

  private static final String VIEW_FORMATTER = "lessons/passwordreset/templates/%s.html";
  static final String PASSWORD_TOM_9 =
      "somethingVeryRandomWhichNoOneWillEverTypeInAsPasswordForTom";
  static final String TOM_EMAIL = "tom@webgoat-cloud.org";
  static final Duration LINK_LIFETIME = Duration.ofMinutes(15);

  /** A reset link together with the account it was issued for. */
  record ResetRequest(String accountEmail, String accountName, Instant expiresAt) {}

  static Map<String, String> usersToTomPassword = Maps.newHashMap();
  static List<String> resetLinks = new ArrayList<>();
  static final Map<String, ResetRequest> resetRequests = new ConcurrentHashMap<>();

  static final String TEMPLATE =
      """
      Hi, you requested a password reset link, please use this <a target='_blank'
       href='%s/PasswordReset/reset/reset-password/%s'>link</a> to reset your
       password.

      If you did not request this password change you can ignore this message.
      If you have any comments or questions, please do not hesitate to reach us at
       support@webgoat-cloud.org

      Kind regards,
      Team WebGoat
      """;

  static void registerResetLink(String link, String email) {
    int at = email.indexOf('@');
    String accountName = at < 0 ? email : email.substring(0, at);
    resetRequests.put(link, new ResetRequest(email, accountName, Instant.now().plus(LINK_LIFETIME)));
    resetLinks.add(link);
  }

  private static ResetRequest validResetRequest(String link) {
    if (!hasText(link)) {
      return null;
    }
    ResetRequest request = resetRequests.get(link);
    if (request == null) {
      return null;
    }
    if (Instant.now().isAfter(request.expiresAt())) {
      resetRequests.remove(link);
      resetLinks.remove(link);
      return null;
    }
    return request;
  }

  @PostMapping("/PasswordReset/reset/login")
  @ResponseBody
  public AttackResult login(
      @RequestParam String password, @RequestParam String email, @CurrentUsername String username) {
    if (TOM_EMAIL.equals(email)) {
      String passwordTom = usersToTomPassword.getOrDefault(username, PASSWORD_TOM_9);
      if (passwordTom.equals(PASSWORD_TOM_9)) {
        return failed(this).feedback("login_failed").build();
      } else if (passwordTom.equals(password)) {
        return success(this).build();
      }
    }
    return failed(this).feedback("login_failed.tom").build();
  }

  @GetMapping("/PasswordReset/reset/reset-password/{link}")
  public ModelAndView resetPassword(@PathVariable(value = "link") String link, Model model) {
    ModelAndView modelAndView = new ModelAndView();
    if (validResetRequest(link) != null) {
      PasswordChangeForm form = new PasswordChangeForm();
      form.setResetLink(link);
      model.addAttribute("form", form);
      modelAndView.addObject("form", form);
      modelAndView.setViewName(
          VIEW_FORMATTER.formatted("password_reset")); // Display html page for changing password
    } else {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
    }
    return modelAndView;
  }

  @PostMapping("/PasswordReset/reset/change-password")
  public ModelAndView changePassword(
      @ModelAttribute("form") PasswordChangeForm form,
      BindingResult bindingResult,
      @CurrentUsername String username) {
    ModelAndView modelAndView = new ModelAndView();
    if (!hasText(form.getPassword())) {
      bindingResult.rejectValue("password", "not.empty");
    }
    if (bindingResult.hasErrors()) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_reset"));
      return modelAndView;
    }
    ResetRequest request = validResetRequest(form.getResetLink());
    // The link must exist, be unexpired and belong to the account of the current user: nobody
    // can change another account's password with a link that was not issued to them.
    if (request == null || username == null || !username.equalsIgnoreCase(request.accountName())) {
      modelAndView.setViewName(VIEW_FORMATTER.formatted("password_link_not_found"));
      return modelAndView;
    }
    // single use
    resetRequests.remove(form.getResetLink());
    resetLinks.remove(form.getResetLink());
    if (TOM_EMAIL.equals(request.accountEmail())) {
      usersToTomPassword.put(username, form.getPassword());
    }
    modelAndView.setViewName(VIEW_FORMATTER.formatted("success"));
    return modelAndView;
  }
}

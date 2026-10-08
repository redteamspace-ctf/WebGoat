/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.ownProfileAltUrl1",
  "idor.hints.ownProfileAltUrl2",
  "idor.hints.ownProfileAltUrl3"
})
public class IDORViewOwnProfileAltUrl implements AssignmentEndpoint {
  private final LessonSession userSessionData;

  public IDORViewOwnProfileAltUrl(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @PostMapping("/IDOR/profile/alt-path")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    Object authenticatedAs = userSessionData.getValue("idor-authenticated-as");
    if (authenticatedAs == null) {
      return failed(this).feedback("idor.view.own.profile.failure2").build();
    }
    // Profiles are only served for the authenticated session through /IDOR/profile; there is
    // no alternative path that selects a profile by a user supplied identifier.
    return failed(this).feedback("idor.view.own.profile.failure1").build();
  }
}

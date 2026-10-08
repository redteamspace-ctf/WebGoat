/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.otherProfile1",
  "idor.hints.otherProfile2",
  "idor.hints.otherProfile3",
  "idor.hints.otherProfile4",
  "idor.hints.otherProfile5",
  "idor.hints.otherProfile6",
  "idor.hints.otherProfile7",
  "idor.hints.otherProfile8",
  "idor.hints.otherProfile9"
})
public class IDOREditOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDOREditOtherProfile(LessonSession lessonSession) {
    this.userSessionData = lessonSession;
  }

  @PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
  @ResponseBody
  public AttackResult completed(
      @PathVariable("userId") String userId, @RequestBody UserProfile userSubmittedProfile) {

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    if (authUserId == null || userSubmittedProfile == null) {
      return failed(this).feedback("idor.edit.profile.failure4").build();
    }

    // Authorization is based on the authenticated session only: the identifier in the URL and
    // the identifier in the body must both refer to the caller's own profile.
    if (!authUserId.equals(userId)
        || (userSubmittedProfile.getUserId() != null
            && !authUserId.equals(userSubmittedProfile.getUserId()))) {
      return failed(this).feedback("idor.edit.profile.failure4").build();
    }

    UserProfile ownProfile = new UserProfile(authUserId);
    if (ownProfile.getUserId() == null) {
      return failed(this).feedback("idor.edit.profile.failure4").build();
    }

    // Only presentation attributes can be changed by the user; the role is an authorization
    // attribute managed by the application and is never taken from the request.
    if (userSubmittedProfile.getRole() != 0 && userSubmittedProfile.getRole() != ownProfile.getRole()) {
      return failed(this).feedback("idor.edit.profile.failure3").build();
    }
    if (userSubmittedProfile.getColor() != null) {
      ownProfile.setColor(userSubmittedProfile.getColor());
    }
    if (userSubmittedProfile.getSize() != null) {
      ownProfile.setSize(userSubmittedProfile.getSize());
    }
    userSessionData.setValue("idor-updated-own-profile", ownProfile);

    return informationMessage(this)
        .output(
            "name: "
                + ownProfile.getName()
                + ", color: "
                + ownProfile.getColor()
                + ", size: "
                + ownProfile.getSize())
        .build();
  }
}

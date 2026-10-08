/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.lessons.missingac.MissingFunctionAC.PASSWORD_SALT_SIMPLE;

import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "access-control.hash.hint1",
  "access-control.hash.hint2",
  "access-control.hash.hint3",
  "access-control.hash.hint4",
  "access-control.hash.hint5"
})
public class MissingFunctionACYourHash implements AssignmentEndpoint {

  private final MissingAccessControlUserRepository userRepository;

  public MissingFunctionACYourHash(MissingAccessControlUserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @PostMapping(
      path = "/access-control/user-hash",
      produces = {"application/json"})
  @ResponseBody
  public AttackResult simple(String userHash, @CurrentUsername String username) {
    // The user listing that exposed the hashes is now restricted to administrators and the
    // hashes are computed with an unpredictable salt, so a hash of another user cannot be
    // obtained or recomputed by a regular user.
    var currentUser = userRepository.findByUsername(username);
    if (currentUser == null || !currentUser.isAdmin()) {
      return failed(this).build();
    }
    User user = userRepository.findByUsername("Jerry");
    DisplayUser displayUser = new DisplayUser(user, PASSWORD_SALT_SIMPLE);
    if (userHash != null && userHash.equals(displayUser.getUserHash())) {
      return failed(this).output("Hash verified for an administrator").build();
    }
    return failed(this).build();
  }
}

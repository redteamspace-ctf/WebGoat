/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import lombok.Getter;

@Getter
public class DisplayUser {
  // intended to provide a display version of WebGoatUser for admins to view user attributes

  private final String username;
  private final boolean admin;
  private String userHash;

  private static final String RUNTIME_SECRET = newRuntimeSecret();

  private static String newRuntimeSecret() {
    byte[] bytes = new byte[32];
    new java.security.SecureRandom().nextBytes(bytes);
    return Base64.getEncoder().encodeToString(bytes);
  }

  public DisplayUser(User user, String passwordSalt) {
    this.username = user.getUsername();
    this.admin = user.isAdmin();

    try {
      this.userHash = genUserHash(user.getUsername(), user.getPassword(), passwordSalt);
    } catch (Exception ex) {
      this.userHash = "Error generating user hash";
    }
  }

  protected String genUserHash(String username, String password, String passwordSalt)
      throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    // Security fix: the hash is bound to an unpredictable, per-instance secret so a leaked
    // or recomputed hash based on the old static salt is worthless.
    String salted = password + passwordSalt + username + RUNTIME_SECRET;
    // md.update(salted.getBytes("UTF-8")); // Change this to "UTF-16" if needed
    byte[] hash = md.digest(salted.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(hash);
  }
}

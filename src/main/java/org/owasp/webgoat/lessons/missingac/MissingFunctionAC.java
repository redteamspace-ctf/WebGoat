/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.missingac;

import org.owasp.webgoat.container.lessons.Category;
import org.owasp.webgoat.container.lessons.Lesson;
import org.springframework.stereotype.Component;

@Component
public class MissingFunctionAC extends Lesson {

  // Salts are generated when the application starts: a salt that is a static value in the
  // source code is predictable and lets anyone recompute the user hashes.
  public static final String PASSWORD_SALT_SIMPLE = randomSalt();
  public static final String PASSWORD_SALT_ADMIN = randomSalt();

  private static String randomSalt() {
    byte[] salt = new byte[32];
    new java.security.SecureRandom().nextBytes(salt);
    return java.util.Base64.getEncoder().encodeToString(salt);
  }

  @Override
  public Category getDefaultCategory() {
    return Category.A1;
  }

  @Override
  public String getTitle() {
    return "missing-function-access-control.title";
  }
}

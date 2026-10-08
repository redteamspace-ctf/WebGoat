/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

public class EncDec {

  // Security fix: the cookie is an HMAC-tagged token signed with a per-instance secret key.
  // The username can no longer be decoded-and-re-encoded for another user, because the tag
  // cannot be produced without the server-side secret.
  private static final byte[] SECRET_KEY = newSecretKey();
  private static final String HMAC_ALG = "HmacSHA256";
  private static final String SEP = "|";

  private EncDec() {}

  private static byte[] newSecretKey() {
    byte[] key = new byte[32];
    new java.security.SecureRandom().nextBytes(key);
    return key;
  }

  private static byte[] tag(String value) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALG);
      mac.init(new SecretKeySpec(SECRET_KEY, HMAC_ALG));
      return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }
    String username = value.toLowerCase();
    String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(tag(username));
    String token = username + SEP + signature;
    return Base64.getEncoder().encodeToString(token.getBytes(StandardCharsets.UTF_8));
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }
    String token = new String(Base64.getDecoder().decode(encodedValue), StandardCharsets.UTF_8);
    int idx = token.lastIndexOf(SEP);
    if (idx < 0) {
      throw new IllegalArgumentException("Malformed authentication token");
    }
    String username = token.substring(0, idx);
    String signature = token.substring(idx + SEP.length());
    String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(tag(username));
    if (!java.security.MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8), signature.getBytes(StandardCharsets.UTF_8))) {
      throw new IllegalArgumentException("Invalid authentication token signature");
    }
    return username;
  }
}

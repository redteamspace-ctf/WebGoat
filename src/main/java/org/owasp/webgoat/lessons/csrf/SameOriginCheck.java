/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;

/**
 * Verifies that a state changing request was issued by a page served from this application. The
 * browser supplied Origin header is used first and the Referer header as a fallback; a request
 * without either, or with another host, is treated as cross-site.
 */
final class SameOriginCheck {

  private SameOriginCheck() {}

  static boolean isSameOrigin(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null || host.isBlank()) {
      return false;
    }
    String origin = request.getHeader("Origin");
    if (origin != null && !origin.isBlank() && !"null".equalsIgnoreCase(origin)) {
      return hostMatches(origin, host);
    }
    String referer = request.getHeader("Referer");
    if (referer != null && !referer.isBlank()) {
      return hostMatches(referer, host);
    }
    return false;
  }

  private static boolean hostMatches(String url, String host) {
    try {
      URI uri = URI.create(url.trim());
      if (uri.getHost() == null) {
        return false;
      }
      String authority = uri.getPort() == -1 ? uri.getHost() : uri.getHost() + ":" + uri.getPort();
      return authority.equalsIgnoreCase(host) || uri.getHost().equalsIgnoreCase(host);
    } catch (IllegalArgumentException e) {
      return false;
    }
  }
}

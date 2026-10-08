/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;
import static org.springframework.http.MediaType.ALL_VALUE;

import com.google.common.collect.Lists;
import jakarta.servlet.http.HttpServletRequest;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.owasp.webgoat.container.CurrentUsername;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"csrf-review-hint1", "csrf-review-hint2", "csrf-review-hint3"})
public class ForgedReviews implements AssignmentEndpoint {

  private static final String ANTI_CSRF_TOKEN = "csrf-review-token";
  private static DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd, HH:mm:ss");

  private static final Map<String, List<Review>> userReviews = new HashMap<>();
  private static final List<Review> REVIEWS = new ArrayList<>();

  private final LessonSession lessonSession;
  private final SecureRandom secureRandom = new SecureRandom();

  static {
    REVIEWS.add(
        new Review("secUriTy", LocalDateTime.now().format(fmt), "This is like swiss cheese", 0));
    REVIEWS.add(new Review("webgoat", LocalDateTime.now().format(fmt), "It works, sorta", 2));
    REVIEWS.add(new Review("guest", LocalDateTime.now().format(fmt), "Best, App, Ever", 5));
    REVIEWS.add(
        new Review(
            "guest",
            LocalDateTime.now().format(fmt),
            "This app is so insecure, I didn't even post this review, can you pull that off too?",
            1));
  }

  public ForgedReviews(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  @GetMapping(
      path = "/csrf/review",
      produces = MediaType.APPLICATION_JSON_VALUE,
      consumes = ALL_VALUE)
  @ResponseBody
  public Collection<Review> retrieveReviews(@CurrentUsername String username) {
    Collection<Review> allReviews = Lists.newArrayList();
    Collection<Review> newReviews = userReviews.get(username);
    if (newReviews != null) {
      allReviews.addAll(newReviews);
    }

    allReviews.addAll(REVIEWS);
    return allReviews;
  }

  /** Hands out the per-session anti-CSRF token the review form has to submit. */
  @GetMapping(path = "/csrf/review/token", produces = MediaType.TEXT_PLAIN_VALUE)
  @ResponseBody
  public String antiCsrfToken() {
    String token = (String) lessonSession.getValue(ANTI_CSRF_TOKEN);
    if (token == null) {
      byte[] bytes = new byte[32];
      secureRandom.nextBytes(bytes);
      token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
      lessonSession.setValue(ANTI_CSRF_TOKEN, token);
    }
    return token;
  }

  @PostMapping("/csrf/review")
  @ResponseBody
  public AttackResult createNewReview(
      String reviewText,
      Integer stars,
      String validateReq,
      HttpServletRequest request,
      @CurrentUsername String username) {

    // A review is only accepted when it is posted from a page of this application together
    // with the unpredictable anti-CSRF token issued to this session.
    if (!SameOriginCheck.isSameOrigin(request)) {
      return failed(this).feedback("csrf-same-host").build();
    }
    String expectedToken = (String) lessonSession.getValue(ANTI_CSRF_TOKEN);
    if (expectedToken == null || !constantTimeEquals(expectedToken, validateReq)) {
      return failed(this).feedback("csrf-you-forgot-something").build();
    }

    Review review = new Review();
    review.setText(reviewText);
    review.setDateTime(LocalDateTime.now().format(fmt));
    review.setUser(username);
    review.setStars(stars);
    var reviews = userReviews.getOrDefault(username, new ArrayList<>());
    reviews.add(review);
    userReviews.put(username, reviews);

    return informationMessage(this).output("Thank you for your review").build();
  }

  private static boolean constantTimeEquals(String expected, String provided) {
    if (provided == null) {
      return false;
    }
    return MessageDigest.isEqual(expected.getBytes(), provided.getBytes());
  }
}

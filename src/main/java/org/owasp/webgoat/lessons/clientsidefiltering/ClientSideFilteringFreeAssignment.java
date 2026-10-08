/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author nbaars
 * @since 4/6/17.
 */
@RestController
@AssignmentHints({
  "client.side.filtering.free.hint1",
  "client.side.filtering.free.hint2",
  "client.side.filtering.free.hint3"
})
public class ClientSideFilteringFreeAssignment implements AssignmentEndpoint {
  /** Historic coupon code, kept for reference only: it is no longer a valid discount code. */
  public static final String SUPER_COUPON_CODE = "get_it_for_free";

  @PostMapping("/clientSideFiltering/getItForFree")
  @ResponseBody
  public AttackResult completed(@RequestParam String checkoutCode) {
    // Discounts are validated on the server against the catalogue of real coupon codes, none of
    // which gives the product away for free; a code found in client-side code is worthless.
    int discount = ShopEndpoint.discountFor(checkoutCode);
    if (discount >= 100) {
      return failed(this).build();
    }
    return failed(this).output("Checkout code '" + checkoutCode + "' gives " + discount + "% discount").build();
  }
}

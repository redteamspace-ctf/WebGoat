/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.bypassrestrictions;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BypassRestrictionsFieldRestrictions implements AssignmentEndpoint {

  @PostMapping("/BypassRestrictions/FieldRestrictions")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String select,
      @RequestParam String radio,
      @RequestParam String checkbox,
      @RequestParam String shortInput,
      @RequestParam String readOnlyInput) {
    // Server-side validation: the browser restrictions are only a convenience, every value is
    // validated again here and a request that does not respect them is rejected.
    boolean valid =
        ("option1".equals(select) || "option2".equals(select))
            && ("option1".equals(radio) || "option2".equals(radio))
            && ("on".equals(checkbox) || "off".equals(checkbox))
            && shortInput.length() <= 5
            && "change".equals(readOnlyInput);
    if (!valid) {
      return failed(this)
          .output("The submitted values do not respect the field restrictions and were rejected")
          .build();
    }
    return failed(this).output("All values respect the field restrictions").build();
  }
}

/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.mitigation;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/**
 * @author nbaars
 * @since 5/21/17.
 */
public class SqlInjectionLesson13Test extends LessonTest {

  @Test
  public void knownAccountShouldDisplayData() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers").param("column", "id"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-dev")));
  }

  @Test
  public void allowedColumnShouldSortByThatColumn() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "hostname"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-acc")));
  }

  @Test
  public void unknownColumnShouldFallBackToId() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "unknown"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-dev")));
  }

  @Test
  public void injectedCaseExpressionShouldNotChangeOrdering() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "CASE WHEN (SELECT ip FROM servers WHERE hostname='webgoat-prd') LIKE '104.%'"
                        + " THEN hostname ELSE id END"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-dev")));
  }

  @Test
  public void injectedSubstrExpressionShouldNotChangeOrdering() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param(
                    "column",
                    "case when (select ip from servers where hostname='webgoat-prd' and"
                        + " substr(ip,1,1) = '1') IS NOT NULL then hostname else id end"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-dev")));
  }

  @Test
  public void injectedBooleanExpressionShouldNotChangeOrdering() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.get("/SqlInjectionMitigations/servers")
                .param("column", "(case when (true) then hostname else id end)"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[0].hostname", is("webgoat-dev")));
  }

  @Test
  public void postingLeakedAddressShouldNotPassTheLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionMitigations/attack12a")
                .param("ip", "104.130.219.202"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  public void postingWrongAnswerShouldNotPassTheLesson() throws Exception {
    mockMvc
        .perform(
            MockMvcRequestBuilders.post("/SqlInjectionMitigations/attack12a")
                .param("ip", "192.168.219.202"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }
}

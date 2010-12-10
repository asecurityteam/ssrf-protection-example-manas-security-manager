/*
 * Copyright (C) 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.security.manas;

import java.security.Permission;

/**
 * Reports security manager policy violation.
 *
 * @author Meder Kydyraliev
 */
public interface SecurityViolationReporter {

  /**
   * Report violation of security policy.
   *
   * @param permission that violated the policy
   * @throws NullPointerException if {@code permission} is {@code null}.
   */
  void reportViolation(Permission permission);
}

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
 * Stores permission and associated authorized class, if any.
 * 
 * @author Meder Kydyraliev
 */
class PermissionEntry {
  private final Permission permission;
  private final String authorizedClass;

  public PermissionEntry(Permission permission, String authorizedClass) {
    this.permission = permission;
    this.authorizedClass = authorizedClass;
  }

  public Permission getPermission() {
    return permission;
  }

  public String getAuthorizedClass() {
    return authorizedClass;
  }
}

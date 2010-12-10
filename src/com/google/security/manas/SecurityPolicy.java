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

/**
 * Interface to configure security policy.
 *
 * @author Meder Kydyraliev
 */
public interface SecurityPolicy {
  /**
   * Add path with the specified permissions to the security policy enforced by
   * the Manas Java Security Manager.
   *
   * @param path path to a file or directory. See
   *             {@link java.io.FilePermission} for supported path wildcards.
   * @param permissions one or more permissions to be allowed on the specified
   *                    path.
   */
  public void addPath(String path, FileOperation... permissions);

  /**
   * Add path with the specified permissions to the security policy enforced by
   * the Manas Java Security Manager.
   *
   * @param path path to a file or directory. See
   *             {@link java.io.FilePermission} for supported path wildcards.
   * @param authorizedClass Class to assign the specified file permissions to.
   *                        This security manager will check for presence of
   *                        the specified class on the execution stack. This
   *                        class needs to be as specific as possible (i.e.
   *                        don't assign sensitive permissions to your main
   *                        class, instead specify the class that's actually
   *                        performing the operation on the specified path).
   * @param permissions one or more permissions to be allowed on the specified
   *                    path.
   */
  public void addPath(String path, String authorizedClass, FileOperation... permissions);
}

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

import com.google.common.base.Preconditions;
import com.google.common.collect.MapMaker;

import java.security.Permission;
import java.util.List;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Class that represents policy enforced by {@link ManasSecurityManager}.
 *
 * @author Meder Kydyraliev
 */
class SecurityManagerPermissions {
    /**
     * Map that associates permission type(class) with a list of {@link PermissionEntry} elements.
     */
    private final ConcurrentMap<Class<? extends Permission>, List<PermissionEntry>>
            permsByPermissionType = new MapMaker().makeMap();

    private boolean isLocked = false;

    void lock() {
        if (isLocked) {
            throw new IllegalStateException("Permissions are already locked");
        }
        isLocked = true;
    }

    void add(Permission permission) {
        Preconditions.checkNotNull(permission);
        addPermission(permission, null);
    }

    void add(Permission permission, String authorizedClass) {
        Preconditions.checkNotNull(authorizedClass);
        Preconditions.checkNotNull(permission);
        addPermission(permission, authorizedClass);
    }

    boolean implies(Permission permissionToCheck) {
        Class<? extends Permission> permClass = permissionToCheck.getClass();
        List<PermissionEntry> permissions = permsByPermissionType.get(permClass);
        if (permissions == null) {
            return false;
        }
        for (PermissionEntry permissionClassPair : permissions) {
            Permission permission = permissionClassPair.getPermission();
            String authorizedClass = permissionClassPair.getAuthorizedClass();
            if (permission.implies(permissionToCheck)) {
                // is there a class specific permission?
                if (authorizedClass != null) {
                    if (isClassOnStack(authorizedClass)) {
                        return true;
                    }
                } else {
                    // no class specific permission and permission is allowed
                    return true;
                }
            }
        }
        return false;
    }

    private void addPermission(Permission permission, String authorizedClass) {
        throwExceptionIfLocked();
        Class<? extends Permission> permClass = permission.getClass();

        List<PermissionEntry> freshPermissions =
                new CopyOnWriteArrayList<PermissionEntry>();
        List<PermissionEntry> permissions =
                permsByPermissionType.putIfAbsent(permClass, freshPermissions);
        if (permissions == null) {
            permissions = freshPermissions;
        }
        permissions.add(new PermissionEntry(permission, authorizedClass));
    }

    private boolean isClassOnStack(String className) {
        Preconditions.checkNotNull(className);
        StackTraceElement[] stack = new Throwable().getStackTrace();
        for (StackTraceElement element : stack) {
            if (element.getClassName().equals(className)) {
                return true;
            }
        }
        return false;
    }

    private void throwExceptionIfLocked() {
        if (isLocked) {
            throw new IllegalStateException("Locked permissions can't be modified");
        }
    }
}
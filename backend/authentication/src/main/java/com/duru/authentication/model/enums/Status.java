package com.duru.authentication.model.enums;

public enum Status {
    ACTIVE("Active"), // Verified/approved and currently allowed to log in.
    PENDING_VERIFICATION("Pending Verification"), // Registered but hasn’t verified email yet.
    SUSPENDED("Suspended"), // Manually suspended by admin or policy.
    DISABLED("Disabled"), // Soft-deactivated (e.g., user requested account closure).
    LOCKED("Locked"), // Temporarily locked due to security events (too many failed attempts)
    DELETED("Deleted");

    private final String value;

    Status(String value) {
        this.value = value;
    }
}

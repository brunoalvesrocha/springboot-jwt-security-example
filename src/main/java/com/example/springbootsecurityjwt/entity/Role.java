package com.example.springbootsecurityjwt.entity;

public enum Role {

    ADMIN, PREMIUM_MEMBER, MEMBER;

    public String authority() {
        return "ROLE_" + this.name();
    }
}

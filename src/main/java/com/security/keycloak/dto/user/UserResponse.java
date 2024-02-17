package com.security.keycloak.dto.user;

import lombok.Data;

import java.util.List;

@Data
public class UserResponse {

    private String id;
    private String email;
    private String firstName;
    private String lastName;
    private List<String> roles;
}
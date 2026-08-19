package com.example.cm.model.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class UserCreateRequest {

    @NotBlank(message = "Username is required")
    @Size(max = 50, message = "Username must be 50 characters or fewer")
    private String username;

    @NotBlank(message = "Password is required")
    @Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
    private String password;

    /** Whether the new user should also be an administrator. */
    private boolean admin;
}

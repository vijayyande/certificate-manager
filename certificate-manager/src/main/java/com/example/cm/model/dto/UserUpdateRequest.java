package com.example.cm.model.dto;

import lombok.Data;

@Data
public class UserUpdateRequest {

    /** Promote/demote the user to/from administrator. */
    private Boolean admin;

    /** Enable or disable the account. */
    private Boolean enabled;
}

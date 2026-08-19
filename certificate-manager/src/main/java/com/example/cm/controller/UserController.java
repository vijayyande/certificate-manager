package com.example.cm.controller;

import com.example.cm.model.dto.ApiResponse;
import com.example.cm.model.dto.PasswordResetRequest;
import com.example.cm.model.dto.UserCreateRequest;
import com.example.cm.model.dto.UserUpdateRequest;
import com.example.cm.model.entity.UserEntity;
import com.example.cm.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin-only user management. Admins can list/create users, grant or revoke the
 * administrator role, enable/disable accounts, reset passwords and delete users.
 */
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping
    public ResponseEntity<List<UserEntity>> list() {
        return ResponseEntity.ok(userService.list());
    }

    @PostMapping
    public ResponseEntity<ApiResponse> create(@Valid @RequestBody UserCreateRequest request) {
        UserEntity user = userService.create(request);
        return ResponseEntity.ok(ApiResponse.ok(
                "User '" + user.getUsername() + "' created", user));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse> update(@PathVariable Long id,
                                              @RequestBody UserUpdateRequest request) {
        UserEntity user = userService.update(id, request);
        return ResponseEntity.ok(ApiResponse.ok("User updated", user));
    }

    @PutMapping("/{id}/password")
    public ResponseEntity<ApiResponse> resetPassword(@PathVariable Long id,
                                                     @Valid @RequestBody PasswordResetRequest request) {
        UserEntity user = userService.resetPassword(id, request);
        return ResponseEntity.ok(ApiResponse.ok(
                "Password reset for '" + user.getUsername() + "'", user));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse> delete(@PathVariable Long id) {
        userService.delete(id);
        return ResponseEntity.ok(ApiResponse.ok("User deleted", null));
    }
}

package com.example.cm.controller;

import com.example.cm.model.dto.ApiResponse;
import com.example.cm.model.dto.ProfileRequest;
import com.example.cm.model.dto.ProfileTypeInfo;
import com.example.cm.model.entity.CertificateProfile;
import com.example.cm.model.enums.ProfileType;
import com.example.cm.service.ProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/profiles")
@RequiredArgsConstructor
public class ProfileController {

    private final ProfileService profileService;

    @GetMapping("/types")
    public ResponseEntity<List<ProfileTypeInfo>> types() {
        return ResponseEntity.ok(Arrays.stream(ProfileType.values())
                .map(t -> new ProfileTypeInfo(t.name(), t.getDescription(), t.getKeyAlgorithm(), t.getKeySize(),
                        t.getValidityDays(), t.isCaProfile(), t.getKeyUsage(), t.getExtendedKeyUsage()))
                .toList());
    }

    @GetMapping
    public ResponseEntity<List<CertificateProfile>> list() {
        return ResponseEntity.ok(profileService.listAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<CertificateProfile> get(@PathVariable Long id) {
        return ResponseEntity.ok(profileService.get(id));
    }

    @PostMapping
    public ResponseEntity<ApiResponse> create(@Valid @RequestBody ProfileRequest request,
                                              Authentication authentication) {
        CertificateProfile profile = profileService.create(request, authentication.getName());
        return ResponseEntity.ok(ApiResponse.ok(
                "Certificate profile '" + profile.getName() + "' created", profile));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse> update(@PathVariable Long id,
                                              @Valid @RequestBody ProfileRequest request) {
        CertificateProfile profile = profileService.update(id, request);
        return ResponseEntity.ok(ApiResponse.ok(
                "Certificate profile '" + profile.getName() + "' updated", profile));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse> delete(@PathVariable Long id) {
        profileService.delete(id);
        return ResponseEntity.ok(ApiResponse.ok("Certificate profile deleted", null));
    }
}

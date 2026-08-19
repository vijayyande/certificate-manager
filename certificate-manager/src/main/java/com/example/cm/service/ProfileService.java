package com.example.cm.service;

import com.example.cm.exception.BusinessException;
import com.example.cm.model.dto.ProfileRequest;
import com.example.cm.model.entity.CertificateProfile;
import com.example.cm.model.enums.KeyStorage;
import com.example.cm.model.enums.ProfileType;
import com.example.cm.repository.CertificateProfileRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
public class ProfileService {

    private final CertificateProfileRepository profileRepository;
    private final CryptoService cryptoService;
    private final AuditService auditService;

    @Transactional
    public CertificateProfile create(ProfileRequest request, String createdBy) {
        if (profileRepository.findByNameIgnoreCase(request.getName()).isPresent()) {
            throw new BusinessException("A profile named '" + request.getName() + "' already exists");
        }
        CertificateProfile profile = apply(request, new CertificateProfile());
        profile.setCreatedBy(createdBy);
        profile.setCreatedAt(LocalDateTime.now());
        profile.setUpdatedAt(LocalDateTime.now());
        profile = profileRepository.save(profile);
        auditService.record(AuditService.currentActor(), "PROFILE", "PROFILE_CREATED",
                "name=" + profile.getName() + ", type=" + profile.getType());
        return profile;
    }

    @Transactional
    public CertificateProfile update(Long id, ProfileRequest request) {
        CertificateProfile profile = get(id);
        profileRepository.findByNameIgnoreCase(request.getName())
                .filter(existing -> !existing.getId().equals(id))
                .ifPresent(existing -> {
                    throw new BusinessException("A profile named '" + request.getName() + "' already exists");
                });
        apply(request, profile);
        profile.setUpdatedAt(LocalDateTime.now());
        profile = profileRepository.save(profile);
        auditService.record(AuditService.currentActor(), "PROFILE", "PROFILE_UPDATED",
                "name=" + profile.getName() + ", type=" + profile.getType());
        return profile;
    }

    private CertificateProfile apply(ProfileRequest request, CertificateProfile profile) {
        ProfileType type = ProfileType.fromString(request.getType());
        boolean preset = type != ProfileType.CUSTOM;

        boolean blankAlg = request.getKeyAlgorithm() == null || request.getKeyAlgorithm().isBlank();
        String algorithm = cryptoService.normalizeKeyAlgorithm(blankAlg && preset ? type.getKeyAlgorithm() : request.getKeyAlgorithm());
        Integer requestedSize = request.getKeySize() != null && request.getKeySize() > 0
                ? request.getKeySize() : (preset ? type.getKeySize() : null);
        int keySize = cryptoService.resolveKeySize(algorithm, requestedSize);
        Integer validityMinutes = null;
        int validityDays;
        if (request.getValidityMinutes() != null) {
            validityMinutes = Math.min(Math.max(request.getValidityMinutes(), 1), 525600);
            validityDays = Math.max(1, (int) Math.ceil(validityMinutes / 1440.0));
        } else if (request.getValidityDays() != null) {
            validityDays = Math.min(Math.max(request.getValidityDays(), 1), 3650);
        } else {
            validityDays = preset ? type.getValidityDays() : 365;
        }
        boolean caProfile = request.getCaProfile() != null
                ? request.getCaProfile() : (preset && type.isCaProfile());
        boolean blankDesc = request.getDescription() == null || request.getDescription().isBlank();
        profile.setName(request.getName().trim());
        profile.setType(type.name());
        profile.setDescription(blankDesc && preset ? type.getDescription() : request.getDescription());
        profile.setKeyAlgorithm(algorithm);
        profile.setKeySize(keySize);
        profile.setValidityDays(validityDays);
        profile.setValidityMinutes(validityMinutes);
        profile.setCaProfile(caProfile);
        profile.setKeyStorage(request.getKeyStorage() != null
                ? request.getKeyStorage() : KeyStorage.DATABASE);
        boolean hasKu = request.getKeyUsage() != null && !request.getKeyUsage().isEmpty();
        boolean hasEku = request.getExtendedKeyUsage() != null && !request.getExtendedKeyUsage().isEmpty();
        profile.setKeyUsage(hasKu ? request.getKeyUsage() : (preset ? type.getKeyUsage() : List.of()));
        profile.setExtendedKeyUsage(hasEku ? request.getExtendedKeyUsage() : (preset ? type.getExtendedKeyUsage() : List.of()));
        profile.setAdditionalExtensions(request.getAdditionalExtensions() == null
                ? List.of() : request.getAdditionalExtensions());
        return profile;
    }

    public String normalizeKeyAlgorithm(String algorithm) {
        return cryptoService.normalizeKeyAlgorithm(algorithm);
    }

    @Transactional(readOnly = true)
    public List<CertificateProfile> listAll() {
        return profileRepository.findAll();
    }

    @Transactional(readOnly = true)
    public List<CertificateProfile> listForCertificates() {
        return profileRepository.findAll().stream().filter(p -> !p.isCaProfile()).toList();
    }

    @Transactional(readOnly = true)
    public CertificateProfile get(Long id) {
        return profileRepository.findById(id)
                .orElseThrow(() -> new BusinessException("Certificate profile not found: " + id));
    }

    @Transactional
    public void delete(Long id) {
        CertificateProfile profile = get(id);
        profileRepository.delete(profile);
        auditService.record(AuditService.currentActor(), "PROFILE", "PROFILE_DELETED",
                "name=" + profile.getName() + ", type=" + profile.getType());
    }
}

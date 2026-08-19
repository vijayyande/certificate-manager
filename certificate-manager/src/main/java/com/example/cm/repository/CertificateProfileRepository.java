package com.example.cm.repository;

import com.example.cm.model.entity.CertificateProfile;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CertificateProfileRepository extends JpaRepository<CertificateProfile, Long> {

    Optional<CertificateProfile> findByNameIgnoreCase(String name);
}

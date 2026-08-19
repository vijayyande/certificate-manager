package com.example.cm.repository;

import com.example.cm.model.entity.CaEntity;
import com.example.cm.model.enums.CertificateStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

public interface CaRepository extends JpaRepository<CaEntity, Long> {

    Optional<CaEntity> findByName(String name);

    Optional<CaEntity> findBySerialNumber(String serialNumber);

    List<CaEntity> findByStatus(CertificateStatus status);

    boolean existsByName(String name);
}

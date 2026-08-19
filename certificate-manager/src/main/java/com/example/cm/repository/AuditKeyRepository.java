package com.example.cm.repository;

import com.example.cm.model.entity.AuditKeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditKeyRepository extends JpaRepository<AuditKeyEntity, Long> {
}

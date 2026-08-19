package com.example.cm.controller;

import com.example.cm.model.dto.AuditVerificationResult;
import com.example.cm.model.entity.AuditLog;
import com.example.cm.repository.AuditLogRepository;
import com.example.cm.service.AuditService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Admin-only signed audit trail. Entries are chained and HMAC-signed by
 * {@link AuditService}; {@code /verify} recomputes the chain and reports
 * whether the log is intact.
 */
@RestController
@RequestMapping("/api/audit")
@RequiredArgsConstructor
public class AuditController {

    private final AuditLogRepository auditLogRepository;
    private final AuditService auditService;

    @GetMapping
    public ResponseEntity<List<AuditLog>> list() {
        return ResponseEntity.ok(auditLogRepository.findAllByOrderByIdAsc());
    }

    @GetMapping("/verify")
    public ResponseEntity<AuditVerificationResult> verify() {
        return ResponseEntity.ok(auditService.verify());
    }
}

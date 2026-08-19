package com.example.cm.repository;

import com.example.cm.model.entity.CertificateEntity;
import com.example.cm.model.enums.CertificateStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

public interface CertificateRepository extends JpaRepository<CertificateEntity, Long> {

    Optional<CertificateEntity> findBySerialNumber(String serialNumber);

    List<CertificateEntity> findByStatus(CertificateStatus status);

    List<CertificateEntity> findByIssuerCaId(Long issuerCaId);

    List<CertificateEntity> findByStatusIn(List<CertificateStatus> statuses);

    List<CertificateEntity> findByIssuerCaIdAndStatusIn(Long issuerCaId, List<CertificateStatus> statuses);

    /**
     * Combined search/filter over every certificate and certificate request (the
     * same table: a request is a certificate, PENDING/ISSUED/...). Case-insensitive
     * match on common name, subject DN, serial number and requester, optionally
     * narrowed by status and/or issuing CA. All filters are optional; nothing
     * filters by owner so both admins and requesters can find anything.
     */
    @Query("""
            SELECT c FROM CertificateEntity c WHERE
                (:q IS NULL
                    OR LOWER(c.commonName) LIKE :q
                    OR LOWER(c.subjectDn) LIKE :q
                    OR LOWER(c.serialNumber) LIKE :q
                    OR LOWER(c.requestedBy) LIKE :q)
                AND (:status IS NULL OR c.status = :status)
                AND (:caId IS NULL OR c.issuerCaId = :caId)
            ORDER BY c.id DESC
            """)
    List<CertificateEntity> search(@Param("q") String q,
                                   @Param("status") CertificateStatus status,
                                   @Param("caId") Long caId);
}

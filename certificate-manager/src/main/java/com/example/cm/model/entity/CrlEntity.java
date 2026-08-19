package com.example.cm.model.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "crl_entries")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CrlEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long caId;

    private String caName;

    private long crlNumber;

    private LocalDateTime thisUpdate;

    private LocalDateTime nextUpdate;

    @Column(columnDefinition = "TEXT")
    private String crlPem;

    private boolean current;

    @Builder.Default
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "crl_revoked_serials", joinColumns = @JoinColumn(name = "crl_id"))
    @Column(name = "serial")
    private List<String> revokedSerials = new ArrayList<>();
}

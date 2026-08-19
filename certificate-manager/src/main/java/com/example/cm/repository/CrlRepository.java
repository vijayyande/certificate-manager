package com.example.cm.repository;

import com.example.cm.model.entity.CrlEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CrlRepository extends JpaRepository<CrlEntity, Long> {

    Optional<CrlEntity> findTopByCaIdAndCurrentTrueOrderByIdDesc(Long caId);

    List<CrlEntity> findByCaIdOrderByIdDesc(Long caId);
}

package com.example.cm.repository;

import com.example.cm.model.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Optional<UserEntity> findByUsername(String username);

    boolean existsByUsername(String username);

    List<UserEntity> findAllByOrderByIdAsc();

    @Query("SELECT COUNT(DISTINCT u) FROM UserEntity u JOIN u.roles r WHERE r = :role")
    long countByRole(@Param("role") String role);
}

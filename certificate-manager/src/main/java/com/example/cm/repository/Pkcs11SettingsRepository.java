package com.example.cm.repository;

import com.example.cm.model.entity.Pkcs11Settings;
import org.springframework.data.jpa.repository.JpaRepository;

public interface Pkcs11SettingsRepository extends JpaRepository<Pkcs11Settings, Long> {
}

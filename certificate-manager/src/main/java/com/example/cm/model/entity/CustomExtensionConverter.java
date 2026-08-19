package com.example.cm.model.entity;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.util.List;

@Converter
public class CustomExtensionConverter implements AttributeConverter<List<CustomExtension>, String> {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<List<CustomExtension>> TYPE = new TypeReference<>() {
    };

    @Override
    public String convertToDatabaseColumn(List<CustomExtension> attribute) {
        try {
            return attribute == null ? "[]" : MAPPER.writeValueAsString(attribute);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize custom extensions", e);
        }
    }

    @Override
    public List<CustomExtension> convertToEntityAttribute(String dbData) {
        try {
            if (dbData == null || dbData.isBlank()) {
                return List.of();
            }
            return MAPPER.readValue(dbData, TYPE);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deserialize custom extensions", e);
        }
    }
}

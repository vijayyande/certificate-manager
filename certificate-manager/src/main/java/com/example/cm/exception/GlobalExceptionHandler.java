package com.example.cm.exception;

import com.example.cm.model.dto.ApiResponse;
import com.example.cm.service.AuditService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private final AuditService auditService;

    public GlobalExceptionHandler(AuditService auditService) {
        this.auditService = auditService;
    }

    @ExceptionHandler(BusinessException.class)
    public ResponseEntity<ApiResponse> handleBusiness(BusinessException ex, HttpServletRequest request) {
        audit(request, "REQUEST_REJECTED", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiResponse.error(ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse> handleValidation(MethodArgumentNotValidException ex,
                                                        HttpServletRequest request) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .collect(Collectors.joining("; "));
        audit(request, "REQUEST_REJECTED", "validation: " + message);
        return ResponseEntity.badRequest().body(ApiResponse.error(message));
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiResponse> handleNotFound(NoResourceFoundException ex, HttpServletRequest request) {
        audit(request, "REQUEST_NOT_FOUND", "path=" + request.getRequestURI());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(ApiResponse.error("Resource not found"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiResponse> handleIllegalArgument(IllegalArgumentException ex,
                                                             HttpServletRequest request) {
        audit(request, "REQUEST_REJECTED", ex.getMessage());
        return ResponseEntity.badRequest().body(ApiResponse.error(ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse> handleGeneric(Exception ex, HttpServletRequest request) {
        log.error("Unhandled exception", ex);
        audit(request, "INTERNAL_ERROR", ex.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("Internal error: " + ex.getMessage()));
    }

    private void audit(HttpServletRequest request, String action, String detail) {
        try {
            String path = request.getRequestURI();
            if (path == null || !path.startsWith("/api/")) {
                return;
            }
            auditService.record(AuditService.currentActor(), "API", action,
                    "path=" + path + ", method=" + request.getMethod() + ", " + detail);
        } catch (Exception ignored) {
            // auditing must never break the API response
        }
    }
}

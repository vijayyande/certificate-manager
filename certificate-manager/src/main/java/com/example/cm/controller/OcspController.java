package com.example.cm.controller;

import com.example.cm.model.dto.ApiResponse;
import com.example.cm.service.OcspService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.util.Map;

@RestController
@RequestMapping("/api/ocsp")
@RequiredArgsConstructor
public class OcspController {

    private final OcspService ocspService;

    @PostMapping(consumes = {"application/ocsp-request", "application/octet-stream", "application/ocsp-response"},
            produces = "application/ocsp-response")
    public ResponseEntity<byte[]> respond(@RequestBody byte[] body) {
        byte[] response = ocspService.respond(body);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/ocsp-response"))
                .body(response);
    }

    @GetMapping("/status/{serialHex}")
    public ResponseEntity<ApiResponse> status(@PathVariable String serialHex) {
        String status = ocspService.checkStatus(serialHex);
        return ResponseEntity.ok(ApiResponse.ok("OCSP status check",
                Map.of("serial", serialHex, "status", status)));
    }

    @GetMapping("/status")
    public ResponseEntity<ApiResponse> statusQuery(@RequestParam String serial) {
        String status = ocspService.checkStatus(serial);
        return ResponseEntity.ok(ApiResponse.ok("OCSP status check",
                Map.of("serial", serial, "status", status)));
    }
}

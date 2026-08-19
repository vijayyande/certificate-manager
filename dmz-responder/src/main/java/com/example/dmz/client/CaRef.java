package com.example.dmz.client;

/**
 * The subset of certificate-manager CA data the responder needs to resolve a
 * CRL distribution point (which references the issuing CA by its serial number,
 * or by numeric id) to the backend's internal CA id.
 *
 * @param id           backend CA id
 * @param serialNumber CA certificate serial (hex string, as embedded in issued
 *                     certificates' CRL distribution point)
 * @param name         human-readable CA name
 */
public record CaRef(long id, String serialNumber, String name) {
}

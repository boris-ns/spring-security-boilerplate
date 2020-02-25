package com.borisns.securitydemo.dto.response;

import org.springframework.http.HttpStatus;

import java.time.ZonedDateTime;

public class ErrorMessageDTO {

    private final String message;
    private final HttpStatus httpStatus;
    private final ZonedDateTime timestamp;

    public ErrorMessageDTO(String message, HttpStatus status, ZonedDateTime timestamp) {
        this.message = message;
        this.httpStatus = status;
        this.timestamp = timestamp;
    }

    public String getMessage() {
        return message;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public ZonedDateTime getTimestamp() {
        return timestamp;
    }
}

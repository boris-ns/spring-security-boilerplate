package com.borisns.securitydemo.exception;

import com.borisns.securitydemo.dto.response.ErrorMessageDTO;
import com.borisns.securitydemo.exception.exceptions.ApiRequestException;
import com.borisns.securitydemo.exception.exceptions.ResourceNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.ZonedDateTime;

@ControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(value = {ApiRequestException.class})
    public ResponseEntity<ErrorMessageDTO> handleApiRequestException(ApiRequestException e) {
        HttpStatus badRequest = HttpStatus.BAD_REQUEST;
        ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO(e.getMessage(), badRequest, ZonedDateTime.now());
        return new ResponseEntity<>(errorMessageDTO, badRequest);
    }

    @ExceptionHandler(value = {ResourceNotFoundException.class})
    public ResponseEntity<ErrorMessageDTO> handleNotFoundException(ApiRequestException e) {
        HttpStatus notFound = HttpStatus.NOT_FOUND;
        ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO(e.getMessage(), notFound, ZonedDateTime.now());
        return new ResponseEntity<>(errorMessageDTO, notFound);
    }

    @ExceptionHandler(value = {MethodArgumentNotValidException.class})
    public ResponseEntity<ErrorMessageDTO> handleMethodArgumentNotValidException(MethodArgumentNotValidException e) {
        HttpStatus badRequest = HttpStatus.BAD_REQUEST;
        String message = e.getBindingResult().getFieldError().getDefaultMessage();
        ErrorMessageDTO errorMessage = new ErrorMessageDTO(message, badRequest, ZonedDateTime.now());
        return new ResponseEntity<>(errorMessage, badRequest);
    }
}

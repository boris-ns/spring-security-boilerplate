package com.borisns.securitydemo.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/hello-world")
public class PrivateHelloWorldController {

    @GetMapping(path = "/registered-user")
    public ResponseEntity<String> helloAnyRegisteredUser() {
        return new ResponseEntity<>("Hello ANY REGISTERED USER from PRIVATE controller!", HttpStatus.OK);
    }

    @GetMapping(path = "/user")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<String> helloUser() {
        return new ResponseEntity<>("Hello USER from PRIVATE controller!", HttpStatus.OK);
    }

    @GetMapping(path = "/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<String> helloAdmin() {
        return new ResponseEntity<>("Hello ADMIN from PRIVATE controller!", HttpStatus.OK);
    }

}

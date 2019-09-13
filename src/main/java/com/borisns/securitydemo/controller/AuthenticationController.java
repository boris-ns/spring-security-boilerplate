package com.borisns.securitydemo.controller;

import com.borisns.securitydemo.dto.UserDTO;
import com.borisns.securitydemo.model.User;
import com.borisns.securitydemo.model.UserTokenState;
import com.borisns.securitydemo.security.TokenUtils;
import com.borisns.securitydemo.security.auth.JwtAuthenticationRequest;
import com.borisns.securitydemo.service.impl.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(value = "/auth", produces = MediaType.APPLICATION_JSON_VALUE)
public class AuthenticationController {

    @Autowired
    private TokenUtils tokenUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService userDetailsService;


    @PostMapping("/login")
    public ResponseEntity<UserDTO> login(@RequestBody JwtAuthenticationRequest authenticationRequest,
                                                             HttpServletResponse response)
            throws AuthenticationException {

        final Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getUsername(),
                        authenticationRequest.getPassword()));

        // Insert username and password into context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Create token
        User user = (User) authentication.getPrincipal();
        String jwt = tokenUtils.generateToken(user.getUsername());
        int expiresIn = tokenUtils.getExpiredIn();

        UserDTO userDto = new UserDTO(user);
        userDto.setToken(new UserTokenState(jwt, expiresIn));

        return ResponseEntity.ok(userDto);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshAuthenticationToken(HttpServletRequest request) {

        String token = tokenUtils.getToken(request);
        String username = this.tokenUtils.getUsernameFromToken(token);
        User user = (User) this.userDetailsService.loadUserByUsername(username);

//        Device device = deviceProvider.getCurrentDevice(request);

        if (this.tokenUtils.canTokenBeRefreshed(token, user.getLastPasswordResetDate())) {
            String refreshedToken = tokenUtils.refreshToken(token);
            int expiresIn = tokenUtils.getExpiredIn();

            return ResponseEntity.ok(new UserTokenState(refreshedToken, expiresIn));
        } else {
            UserTokenState userTokenState = new UserTokenState();
            return ResponseEntity.badRequest().body(userTokenState);
        }
    }

    @PostMapping("/change-password")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> changePassword(@RequestBody PasswordChanger passwordChanger) {
        userDetailsService.changePassword(passwordChanger.oldPassword, passwordChanger.newPassword);

        Map<String, String> result = new HashMap<>();
        result.put("result", "success");
        return ResponseEntity.accepted().body(result);
    }

    static class PasswordChanger {
        public String oldPassword;
        public String newPassword;
    }
}

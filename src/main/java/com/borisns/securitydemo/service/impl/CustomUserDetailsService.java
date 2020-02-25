package com.borisns.securitydemo.service.impl;

import com.borisns.securitydemo.dto.response.UserDTO;
import com.borisns.securitydemo.exception.exceptions.ApiRequestException;
import com.borisns.securitydemo.model.User;
import com.borisns.securitydemo.dto.response.UserTokenDTO;
import com.borisns.securitydemo.repository.UserRepository;
import com.borisns.securitydemo.security.TokenUtils;
import com.borisns.securitydemo.dto.request.LoginDTO;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    protected final Log LOGGER = LogFactory.getLog(getClass());

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenUtils tokenUtils;

    @Autowired
    private AuthenticationManager authenticationManager;


    /* Return User from database */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
        } else {
            return user;
        }
    }

    /* Change User's password */
    public void changePassword(String oldPassword, String newPassword) {
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
        String username = currentUser.getName();

        if (authenticationManager != null) {
            LOGGER.debug("Re-authenticating user '" + username + "' for password change request.");
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, oldPassword));
        } else {
            LOGGER.debug("No authentication manager set. can't change Password!");
            return;
        }

        LOGGER.debug("Changing password for user '" + username + "'");

        User user = (User) loadUserByUsername(username);
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public UserDTO login(LoginDTO authenticationRequest) throws ApiRequestException {
        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(
                            authenticationRequest.getUsername(),
                            authenticationRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new ApiRequestException("Credentials are not valid!");
        }

        // Insert username and password into context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Create token
        User user = (User) authentication.getPrincipal();
        String jwt = tokenUtils.generateToken(user.getUsername());
        int expiresIn = tokenUtils.getExpiredIn();

        UserDTO userDto = new UserDTO(user);
        userDto.setToken(new UserTokenDTO(jwt, expiresIn));

        return userDto;
    }

    public UserTokenDTO refreshAuthenticationToken(HttpServletRequest request) throws ApiRequestException {
        String token = tokenUtils.getToken(request);
        String username = tokenUtils.getUsernameFromToken(token);
        User user = (User) loadUserByUsername(username);

        if (tokenUtils.canTokenBeRefreshed(token, user.getLastPasswordResetDate())) {
            String refreshedToken = tokenUtils.refreshToken(token);
            int expiresIn = tokenUtils.getExpiredIn();
            return new UserTokenDTO(refreshedToken, expiresIn);
        } else {
            throw new ApiRequestException("Token can not be refreshed.");
        }
    }
}

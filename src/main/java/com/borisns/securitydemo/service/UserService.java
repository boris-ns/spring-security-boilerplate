package com.borisns.securitydemo.service;

import com.borisns.securitydemo.dto.response.UserDTO;

import java.util.List;

public interface UserService {

    UserDTO findById(Long id);
    UserDTO findByUsername(String username);
    List<UserDTO> findAll();
}

package com.borisns.securitydemo.service;

import com.borisns.securitydemo.model.User;

import java.util.List;

public interface UserService {

    User findById(Long id);
    User findByUsername(String username);
    List<User> findAll();
}

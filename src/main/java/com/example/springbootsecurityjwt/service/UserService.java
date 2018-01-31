package com.example.springbootsecurityjwt.service;

import com.example.springbootsecurityjwt.entity.User;

import java.util.Optional;

public interface UserService {

    Optional<User> getByUsername(String username);
}

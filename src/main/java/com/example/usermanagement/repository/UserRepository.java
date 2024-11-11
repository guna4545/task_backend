package com.example.usermanagement.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.usermanagement.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}

package com.duru.authentication.repository;

import com.duru.authentication.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String Email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}

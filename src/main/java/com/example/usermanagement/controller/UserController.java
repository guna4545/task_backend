package com.example.usermanagement.controller;

import com.example.usermanagement.model.User;
import com.example.usermanagement.security.JwtUtil;
import com.example.usermanagement.service.TokenBlacklistService;
import com.example.usermanagement.service.UserService;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping("/api")
public class UserController {
    @Autowired
    private UserService userService;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @Autowired
    JwtUtil jwtUtil;
    
    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user) {
    	User existingUser = userService.findByUsername(user.getUsername());
    	if (existingUser == null) {
    		return ResponseEntity.ok(userService.save(user).getId().toString());
    	}
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body("User already exist.");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        User existingUser = userService.findByUsername(user.getUsername());
        Map<String, String> tokenResponse = new HashMap<String, String>();
        if (existingUser != null && passwordEncoder.matches(user.getPassword(), existingUser.getPassword())) {
            tokenResponse.put("token", jwtUtil.createToken(existingUser.getUsername()));
            return ResponseEntity.ok(tokenResponse);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials or User not found.");
    }

    @GetMapping("/user")
    public ResponseEntity<?> getUserProfile(@RequestParam("username") String username) {
    	User user = userService.findByUsername(username);
    	if(user != null) {
    		return ResponseEntity.ok(user);
    	}
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found.");
    }
    
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String token) {
    	if (token != null && token.startsWith("Bearer ")) {
            String jwt = token.substring(7);
            tokenBlacklistService.addToBlacklist(jwt);
            HashMap<String, String> map = new HashMap<String, String>();
            map.put("message", "Logged out successfully");
            return ResponseEntity.ok(map);
        }
        return ResponseEntity.badRequest().body("Invalid token");
    }
}

package com.phegondev.usersmanagementsystem.service;

import com.phegondev.usersmanagementsystem.dto.ReqRes;
import com.phegondev.usersmanagementsystem.entity.OurUsers;
import com.phegondev.usersmanagementsystem.repository.UsersRepo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;

@Service
public class UsersManagementService {

    @Autowired
    private UsersRepo usersRepo;

    @Autowired
    private JWTUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // Register a new user
    public ReqRes register(ReqRes registrationRequest) {
        ReqRes resp = new ReqRes();
        try {
            OurUsers user = new OurUsers();
            user.setEmail(registrationRequest.getEmail());
            user.setCity(registrationRequest.getCity());
            user.setRole(registrationRequest.getRole());
            user.setName(registrationRequest.getName());
            user.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));

            OurUsers savedUser = usersRepo.save(user);
            resp.setOurUsers(savedUser);
            resp.setMessage("User saved successfully.");
            resp.setStatusCode(200);
        } catch (Exception e) {
            resp.setStatusCode(500);
            resp.setError(e.getMessage());
        }
        return resp;
    }

    // Login
    public ReqRes login(ReqRes loginRequest) {
        ReqRes response = new ReqRes();
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
            );

            OurUsers user = usersRepo.findByEmail(loginRequest.getEmail()).orElseThrow();
            String jwt = jwtUtils.generateToken(user);
            String refreshToken = jwtUtils.generateRefreshToken(new HashMap<>(), user);

            response.setStatusCode(200);
            response.setToken(jwt);
            response.setRole(user.getRole());
            response.setRefreshToken(refreshToken);
            response.setExpirationTime("24Hrs");
            response.setMessage("Successfully logged in.");
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage(e.getMessage());
        }
        return response;
    }

    // Refresh token
    public ReqRes refreshToken(ReqRes refreshTokenRequest) {
        ReqRes response = new ReqRes();
        try {
            String email = jwtUtils.extractUsername(refreshTokenRequest.getToken());
            OurUsers user = usersRepo.findByEmail(email).orElseThrow();

            if (jwtUtils.isTokenValid(refreshTokenRequest.getToken(), user)) {
                String newJwt = jwtUtils.generateToken(user);
                response.setToken(newJwt);
                response.setRefreshToken(refreshTokenRequest.getToken());
                response.setExpirationTime("24Hr");
                response.setStatusCode(200);
                response.setMessage("Token refreshed successfully.");
            }
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage(e.getMessage());
        }
        return response;
    }

    // Get all users
    public ReqRes getAllUsers() {
        ReqRes resp = new ReqRes();
        try {
            List<OurUsers> users = usersRepo.findAll();
            if (!users.isEmpty()) {
                resp.setOurUsersList(users);
                resp.setStatusCode(200);
                resp.setMessage("Users fetched successfully.");
            } else {
                resp.setStatusCode(404);
                resp.setMessage("No users found.");
            }
        } catch (Exception e) {
            resp.setStatusCode(500);
            resp.setMessage("Error occurred: " + e.getMessage());
        }
        return resp;
    }

    // Get user by ID
    public ReqRes getUsersById(Integer id) {
        ReqRes resp = new ReqRes();
        try {
            OurUsers user = usersRepo.findById(id).orElseThrow(() -> new RuntimeException("User not found."));
            resp.setOurUsers(user);
            resp.setStatusCode(200);
            resp.setMessage("User found successfully.");
        } catch (Exception e) {
            resp.setStatusCode(500);
            resp.setMessage(e.getMessage());
        }
        return resp;
    }

    // Delete user
    public ReqRes deleteUser(Integer id) {
        ReqRes resp = new ReqRes();
        try {
            if (usersRepo.existsById(id)) {
                usersRepo.deleteById(id);
                resp.setStatusCode(200);
                resp.setMessage("User deleted successfully.");
            } else {
                resp.setStatusCode(404);
                resp.setMessage("User not found.");
            }
        } catch (Exception e) {
            resp.setStatusCode(500);
            resp.setMessage(e.getMessage());
        }
        return resp;
    }

    // Update user
    public ReqRes updateUser(Integer id, OurUsers updatedUser) {
        ReqRes resp = new ReqRes();
        try {
            OurUsers existingUser = usersRepo.findById(id).orElseThrow(() -> new RuntimeException("User not found."));
            existingUser.setEmail(updatedUser.getEmail());
            existingUser.setName(updatedUser.getName());
            existingUser.setCity(updatedUser.getCity());
            existingUser.setRole(updatedUser.getRole());

            if (updatedUser.getPassword() != null && !updatedUser.getPassword().isEmpty()) {
                existingUser.setPassword(passwordEncoder.encode(updatedUser.getPassword()));
            }

            resp.setOurUsers(usersRepo.save(existingUser));
            resp.setStatusCode(200);
            resp.setMessage("User updated successfully.");
        } catch (Exception e) {
            resp.setStatusCode(500);
            resp.setMessage(e.getMessage());
        }
        return resp;
    }

    // Get user info by email
    public ReqRes getMyInfo(String email) {
        ReqRes resp = new ReqRes();
        try {
            OurUsers user = usersRepo.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found."));
            resp.setOurUsers(user);
            resp.setStatusCode(200);
            resp.setMessage("User information fetched successfully.");
        } catch (Exception e) {
            resp.setStatusCode(500);
            resp.setMessage(e.getMessage());
        }
        return resp;
    }
}

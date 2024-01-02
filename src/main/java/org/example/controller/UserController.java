package org.example.controller;

import org.example.model.User;
import org.example.service.UserService;
import org.example.service.MyUserDetailsService;
import org.example.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Map;

@Controller
public class UserController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final MyUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    @Autowired
    public UserController(UserService userService, PasswordEncoder passwordEncoder, MyUserDetailsService userDetailsService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String register(@ModelAttribute User user, Model model, RedirectAttributes redirectAttributes) {
        // Validate the user input
        if (user.getPassword() == null || user.getPassword().isEmpty()) {
            model.addAttribute("error", "Password cannot be null or empty");
            return "register";
        }

        // Check if the email is already in use
        if (userService.findByEmail(user.getEmail()) != null) {
            model.addAttribute("error", "Email already in use");
            return "register";
        }

        try {
            // Save the user
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            String result = userService.save(user);
            if (result.equals("Email already in use")) {
                model.addAttribute("error", result);
                return "register";
            }
        } catch (Exception e) {
            // Log the exception (consider using a logging framework)
            System.err.println("Error saving user: " + e.getMessage());
            model.addAttribute("error", "Error saving user");
            return "register";
        }

        // Redirect to login page with a success flash attribute
        redirectAttributes.addFlashAttribute("success", true);
        return "redirect:/login";
    }


    @GetMapping("/password-recovery")
    public String showPasswordRecoveryForm() {
        return "password-recovery";
    }

    @PostMapping("/password-recovery")
    public ResponseEntity<String> passwordRecovery(@RequestBody String email) {
        User user = userService.findByEmail(email);
        if (user == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("No user found with this email");
        }
        // Implement sending the email with the recovery link
        // This depends on how you handle email sending in your application
        return ResponseEntity.ok("Password recovery email sent");
    }

    @PostMapping("/password-reset")
    public String passwordReset(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String newPassword = body.get("password");
        // Implement the password reset
        return "Password reset successful";
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        System.out.println("Attempting to login user: " + user.getEmail());
        System.out.println("Received login request with email: " + user.getEmail());
        System.out.println("Received login request with password: " + user.getPassword());

        User existingUser = userService.findByEmail(user.getEmail());

        if (existingUser != null) {
            System.out.println("Found user in database: " + existingUser.getEmail());
            boolean isMatch = userService.checkPassword(user.getPassword(), existingUser.getPassword());

            System.out.println("Password matches: " + isMatch);

            if (isMatch) {
                String jwt = userService.login(existingUser);  // Use existingUser instead of user
                if (jwt != null) {
                    System.out.println("Generated JWT: " + jwt);
                    return ResponseEntity.ok(jwt);
                } else {
                    System.out.println("JWT generation failed");
                }
            }
        } else {
            System.out.println("No user found in database with email: " + user.getEmail());
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
    }


    @GetMapping("/test")
    public void testCheckPassword() {
        String rawPassword = "4444"; // thay đổi này thành mật khẩu thực tế
        String encodedPassword = "$2a$10$sb7UZO6RUZcN5BdcbhyuBO1x.O/2HcGKnik3M6IdQzfbbuuAbNN6K"; // thay đổi này thành mật khẩu đã mã hóa thực tế
        boolean isMatch = userService.checkPassword(rawPassword, encodedPassword);
        System.out.println("Password matches: " + isMatch);
    }
}

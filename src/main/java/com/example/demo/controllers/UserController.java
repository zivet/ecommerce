package com.example.demo.controllers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.demo.security.SecurityConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.model.persistence.Cart;
import com.example.demo.model.persistence.User;
import com.example.demo.model.persistence.repositories.CartRepository;
import com.example.demo.model.persistence.repositories.UserRepository;
import com.example.demo.model.requests.CreateUserRequest;

import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/user")
public class UserController {

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private CartRepository cartRepository;

	@GetMapping("/id/{id}")
	public ResponseEntity<User> findById(@PathVariable Long id) {
		return ResponseEntity.of(userRepository.findById(id));
	}

	@PreAuthorize("authenticated")
	@GetMapping("/{username}")
	public ResponseEntity<User> findByUserName(@PathVariable String username) {
		User user = userRepository.findByUsername(username);
		return user == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(user);
	}
	
	@PostMapping("/create")
	public ResponseEntity<User> createUser(@RequestBody CreateUserRequest createUserRequest) {
		User user = new User();
		user.setUsername(createUserRequest.getUsername());
		Cart cart = new Cart();
		cartRepository.save(cart);
		user.setCart(cart);
		if(createUserRequest.getPassword().length() > 7 ||
				!createUserRequest.getPassword().equals(createUserRequest.getConfirmPassword())) {
			return ResponseEntity.badRequest().build();
		}
		user.setPassword(passwordEncoder.encode(createUserRequest.getPassword()));
		userRepository.save(user);
		return ResponseEntity.ok(user);
	}

	@PreAuthorize("authenticated")
	@GetMapping("/token")
	public String token(@AuthenticationPrincipal org.springframework.security.core.userdetails.User user) throws UnsupportedEncodingException {
		String username = user.getUsername().toString();
		String[] authorities = user.getAuthorities().stream().map(a -> a.getAuthority().toString()).collect(Collectors.toList()).toArray(new String[0]);
		return JWT.create().withIssuer("IOVERLAP")
				.withIssuedAt(new Date())
				.withNotBefore(new Date())
				.withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
				.withClaim("username", username)
				.withArrayClaim("authorities", authorities)
				.sign(Algorithm.HMAC256("MY_SECRET_KEY"));
	}
	
}

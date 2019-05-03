package uk.cetinkaya.message.controller;

import java.util.HashSet;
import java.util.Set;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import uk.cetinkaya.message.request.LoginForm;
import uk.cetinkaya.message.request.SignUpForm;
import uk.cetinkaya.message.response.JwtResponse;
import uk.cetinkaya.model.Role;
import uk.cetinkaya.model.RoleName;
import uk.cetinkaya.model.User;
import uk.cetinkaya.repository.RoleRepository;
import uk.cetinkaya.repository.UserRepository;
import uk.cetinkaya.security.JwtProvider;

@CrossOrigin(origins="*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthRestAPIs {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private RoleRepository roleRepository;
	
	@Autowired
	private PasswordEncoder encoder;
	
	@Autowired
	private JwtProvider jwtProvider;
	
	
	@PostMapping("signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginForm loginRequest){
		
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						loginRequest.getUsername(),
						loginRequest.getPassword()
						)
		);
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtProvider.generateJwtToken(authentication);
		return ResponseEntity.ok(new JwtResponse(jwt));
		
	}
	
	
	@PostMapping("signup")
	public ResponseEntity<String> registerUser(@Valid @RequestBody SignUpForm signupRequest) {
		
		if(userRepository.existsByUsername(signupRequest.getUsername())) {
			return new ResponseEntity<String>("Fail -> Username is already taken!", HttpStatus.BAD_REQUEST);
		}
		
		if(userRepository.existsByEmail(signupRequest.getEmail())) {
			return new ResponseEntity<String>("Fail -> Email is already in use by another user!", HttpStatus.BAD_REQUEST);
		}
		
		//Create user's account
		User user = new User(signupRequest.getName(), signupRequest.getUsername(), signupRequest.getEmail(), encoder.encode(signupRequest.getPassword()));
		
		Set<String> strRoles = signupRequest.getRole();
		Set<Role> roles = new HashSet<>();
		
		strRoles.forEach(role -> {
			switch(role) {
			case "admin": 
				Role adminRole = roleRepository.findByName(RoleName.ROLE_ADMIN)
					.orElseThrow(() -> new RuntimeException("Fail -> Cause: User Role not found!")
							);
				roles.add(adminRole);
				break;
				
			case "pm": 
				Role pmRole = roleRepository.findByName(RoleName.ROLE_PM)
					.orElseThrow(() -> new RuntimeException("Fail -> Cause: User Role not found!")
							);
				roles.add(pmRole);
				break;
				
			default: 
				Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Fail -> Cause: User Role not found!")
							);
				roles.add(userRole);
			}
			
		});
		
		user.setRoles(roles);
		userRepository.save(user);
		
		return ResponseEntity.ok().body("User registered successfully!");
	}
	
	
	
}

/**
 * 
 */
package com.pension.authorization.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.pension.authorization.configuration.JwtAuthorizationUtil;
import com.pension.authorization.exception.AuthorizationException;
import com.pension.authorization.model.AuthorizationResponse;
import com.pension.authorization.model.JwtRequest;

import lombok.extern.slf4j.Slf4j;

/**
 * @author SAYANDIP PAUL
 *
 */
@RestController
@CrossOrigin
@Slf4j
@RequestMapping(value = "/api")
public class JwtAuthenticationController {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private JwtAuthorizationUtil jwtAuthorizationUtil;
	
	@PostMapping(value = "/authenticate")
	public AuthorizationResponse createAuthToken(@RequestBody JwtRequest jwtRequest) {
		log.info("User details inside create token {}", jwtRequest);
		AuthorizationResponse response = new AuthorizationResponse();
		try {
			log.info("authenticating User details {}", jwtRequest);
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jwtRequest.getUsername(), jwtRequest.getPassword()));
			UserDetails userDetails = userDetailsService.loadUserByUsername(jwtRequest.getUsername());
			String token = this.jwtAuthorizationUtil.generateToken(userDetails);
			response.setMessage("Successfully logged-in");
			response.setStatusCode(200);
			response.setToken(token);
		}catch (Exception e) {
			log.error("Bad credentials {}", jwtRequest);
			response.setMessage("Bad credentials");
			response.setStatusCode(400);
			response.setToken("");
		}
		log.info("End of User details authentication {}", jwtRequest);
		return response;
	}
	
	@GetMapping(value = "/authorize/{token}")
	public AuthorizationResponse authorizeRequest(@PathVariable("token") String token) {
		log.info("Authorize inside authorizeRequest {}", token);
		String userName = "";
		AuthorizationResponse response = new AuthorizationResponse();
		try {
			log.info("Authorize the token {}", token);
			userName = jwtAuthorizationUtil.getUsernameFromToken(token);
			if(userName != null) {
				response.setMessage("Valid Token");
				response.setStatusCode(200);
				response.setToken(token);
				log.info("Authorize the token Successfully user name => {}", userName);
			}else {
				throw new AuthorizationException("In-valid Token");
			}
		}catch (AuthorizationException e) {
			log.error("Authorize the token Not Successfully");
			response.setMessage("Not-Valid Token");
			response.setStatusCode(400);
			response.setToken("Not valid");
		}catch (Exception e) {
			log.error("Authorize the token Not Successfully");
			response.setMessage("Not-Valid Token");
			response.setStatusCode(400);
			response.setToken("Not valid");
		}
		log.info("Authorize End authorizeRequest ");
		return response;
	}
}

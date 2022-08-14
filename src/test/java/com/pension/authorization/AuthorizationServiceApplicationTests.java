package com.pension.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;

import com.pension.authorization.configuration.JwtAuthorizationUtil;
import com.pension.authorization.controller.JwtAuthenticationController;
import com.pension.authorization.exception.AuthorizationException;
import com.pension.authorization.model.AuthorizationResponse;
import com.pension.authorization.model.JwtRequest;
import com.pension.authorization.repository.UserDetailsDao;
import com.pension.authorization.service.JwtUserDetailsService;

import io.jsonwebtoken.Claims;

@SpringBootTest
class AuthorizationServiceApplicationTests {

	private AuthorizationException exception = new AuthorizationException("message");
	
	
	UserDetails userDetails;
	
	@Autowired
	private JwtAuthorizationUtil util;
	
	@Autowired
	private UserDetailsDao dao;
	
	@Autowired
	private AuthenticationEntryPoint entryPoint;
	
	@MockBean
	Claims claims;
	
	private JwtRequest request = new JwtRequest("admin","admin");
	
	@Mock
	private UserDetailsDao detailsDao;
	
	@Mock
	private PasswordEncoder encoder;
	
	@Mock
	private JwtAuthenticationController controller;
	
	@InjectMocks
	private JwtUserDetailsService service;
	
	private AuthorizationResponse authorizationResponse;
	
	@BeforeEach
	void setUp() throws Exception {
		authorizationResponse = new AuthorizationResponse("token","Successfully logged-in",200);
	}
	
	@Test
	void contextLoads() {
	}
	
	@Test
	void main() {
		AuthorizationServiceApplication.main(new String[]{});
	}
	
	
	@Test
	void testMessageSetter() {
		assertThat(exception).isNotNull();
	}
	
	@Test
	public void testgenerateTokenGetNull() {
		UserDetails details = new org.springframework.security.core.userdetails.User("admin","admin", new ArrayList<>());
		assertThat(util.generateToken(details)).isNotNull();
				
	}
	
	@Test
	void validateTokenTest() {
		userDetails = new User("admin","admin", new ArrayList<>());
		String generateToken = util.generateToken(userDetails);
		Boolean validateToken = util.validateToken(generateToken, userDetails);
		assertThat(validateToken).isTrue();
	}
	
	@Test
	void testUserNameGetter() {
		assertThat(request.getUsername().equals("admin")).isTrue();
	}
	
	@Test
	void testPasswordGetter() {
		assertThat(request.getPassword().equals("admin")).isTrue();
	}
	
	@Test
	void loadUserByuserNameThrowException() {
		when(detailsDao.findByUsername("wrongName")).thenReturn(null);
		assertThatThrownBy(()-> service.loadUserByUsername("wrongname"))
		.isInstanceOf(UsernameNotFoundException.class)
		.hasMessage("User not found");
		verify(detailsDao,Mockito.times(1)).findByUsername("wrongname");
	}
	
	@Test
	void loadUserByUsernameShouldGiveUserName() {
		when(detailsDao.findByUsername("admin")).thenReturn(new com.pension.authorization.model.User(1,"admin","admin"));
		assertThat(service.loadUserByUsername("admin")).isNotNull();
		verify(detailsDao,Mockito.times(1)).findByUsername("admin");
	}
	
	@Test
	void testUserDao() {
		com.pension.authorization.model.User user = new com.pension.authorization.model.User(1,"admin","admin");
		when(detailsDao.findByUsername("admin")).thenReturn(user);
		assertThat(detailsDao.findByUsername("admin").equals(user));
	}
	
	@Test
	void testResponseClass() {
		assertThat(authorizationResponse.getToken().equalsIgnoreCase("token"));
		assertThat(authorizationResponse.getMessage().equalsIgnoreCase("Successfully logged-in"));
	}
	
	@Test 
	void testValidToken() {
		JwtAuthenticationController controller = new JwtAuthenticationController();
		UserDetails userDetails = new org.springframework.security.core.userdetails.User("admin","admin", new ArrayList<>());
		JwtAuthorizationUtil util = new JwtAuthorizationUtil();
		String generateToken = util.generateToken(userDetails);
		assertThat(util.validateToken(generateToken, userDetails)).isTrue();
	}
	
	@Test
	void commence_setsHeaderAndStatus() throws IOException, ServletException {
	    MockHttpServletRequest request = new MockHttpServletRequest();
	    MockHttpServletResponse response = new MockHttpServletResponse();
	    
	    entryPoint.commence(request, response, new BadCredentialsException("Credentials are invalid"));
	    assertThat(response.getErrorMessage()).isEqualTo("Unauthorized");
	}
	
}

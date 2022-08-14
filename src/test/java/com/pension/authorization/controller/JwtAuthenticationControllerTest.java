package com.pension.authorization.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultHandler;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pension.authorization.configuration.JwtAuthorizationUtil;
import com.pension.authorization.exception.AuthorizationException;
import com.pension.authorization.model.AuthorizationResponse;
import com.pension.authorization.model.CustomUserDetails;
import com.pension.authorization.model.JwtRequest;
import com.pension.authorization.model.User;
import com.pension.authorization.repository.UserDetailsDao;
import com.pension.authorization.service.JwtUserDetailsService;

@SpringBootTest
@AutoConfigureMockMvc
public class JwtAuthenticationControllerTest {

	
	@BeforeEach
	public void init() {
		MockitoAnnotations.initMocks(this);
	}
	
	@Autowired
	private MockMvc mockMvc;
	
	@Autowired
	@MockBean
	private UserDetailsDao dao;
	
	@MockBean
	private AuthenticationManager authenticationManager;
	
	@MockBean
	private JwtAuthorizationUtil jwtAuthorizationUtil;
	
	@MockBean
	private JwtAuthenticationController controller;
	
	@MockBean
	private JwtUserDetailsService userDetailsService;
	
	
	@Test
	public void testAuthorization() {
		JwtRequest jwtRequest= new JwtRequest("admin","admin");
		AuthorizationResponse authorizationResponse = new AuthorizationResponse();
		authorizationResponse.setMessage("Successfully logged-in");
		authorizationResponse.setStatusCode(200);
		authorizationResponse.setToken("token");
		when(jwtAuthorizationUtil.getUsernameFromToken("Bearer token")).thenReturn(null);
		assertThat(controller.authorizeRequest("token")).isEqualTo(null);
		assertThat(controller.authorizeRequest("token")).isEqualTo(null);
		when(controller.createAuthToken(jwtRequest)).thenReturn(authorizationResponse);
		try {
			mockMvc.perform(MockMvcRequestBuilders.get("/api/authorize/"))
			.andExpect(status().isNotFound());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Test
	public void testAuthorizationInvalid() {
		User user = new User(1,"admin","admin");
		UserDetails details = new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), new ArrayList<>());
		when(userDetailsService.loadUserByUsername("admin")).thenReturn(details);
		when(jwtAuthorizationUtil.getUsernameFromToken("token")).thenReturn("admin");
		assertEquals(controller.authorizeRequest("token"),null);
	}
	
	@SuppressWarnings("deprecation")
	@Test
	public void testAuthorizationgetTokentrue() throws Exception {
		JwtRequest jwtRequest= new JwtRequest("admin","admin");
		authenticationManager.authenticate(new UsernamePasswordAuthenticationToken
				(jwtRequest.getUsername(), jwtRequest.getPassword()));
		UserDetails details = userDetailsService.loadUserByUsername(jwtRequest.getUsername());
		String token = jwtAuthorizationUtil.generateToken(userDetailsService.loadUserByUsername(jwtRequest.getUsername()));
		AuthorizationResponse response = controller.createAuthToken(jwtRequest);
		assertEquals(controller.authorizeRequest(token), response);
	}
	
	@Test
	void textExistingUserAuthorize() throws Exception {
		User user = new User(1, "admin", "pass");
		UserDetails details = new org.springframework.security.core.userdetails.User(user.getUsername(),
				user.getPassword(), new ArrayList<>());
		when(userDetailsService.loadUserByUsername("admin")).thenReturn(details);
		when(jwtAuthorizationUtil.getUsernameFromToken("token")).thenReturn("admin");
		mockMvc.perform(MockMvcRequestBuilders.get("/api/authorize/{token}","Bearer token"))
				.andExpect(status().isOk());

	}
	
	@Test
	void textNullTokenAuthorize() throws Exception {
		User user = new User(1, "admin", "pass");
		UserDetails details = new org.springframework.security.core.userdetails.User(user.getUsername(),
				user.getPassword(), new ArrayList<>());
		when(userDetailsService.loadUserByUsername("admin")).thenReturn(details);
		when(jwtAuthorizationUtil.getUsernameFromToken("token")).thenReturn("admin");
		mockMvc.perform(MockMvcRequestBuilders.get("/api/authorize/{token}","").header("Authorization", "")
				.contentType(MediaType.APPLICATION_JSON)).andExpect(status().isNotFound());

	}
	
	@Test
	void testBadRequestGenerateToken() throws Exception {
		System.out.println(mockMvc.perform(post("/api/authenticate")));
		mockMvc.perform(post("/api/authenticate")).andExpect(status().isBadRequest());
	}
	
	@Test
	void testAuthorizedGenerateToken() throws Exception {

		User user = new User(1, "admin", "admin123");
		UserDetails details = new org.springframework.security.core.userdetails.User(user.getUsername(),
				user.getPassword(), new ArrayList<>());
		when(jwtAuthorizationUtil.generateToken(details)).thenReturn("Bearer @token@token");
		when(userDetailsService.loadUserByUsername("admin")).thenReturn(details);
		ObjectMapper mapper = new ObjectMapper();
		String jsonString = mapper.writeValueAsString(new JwtRequest("admin", "admin123"));
		this.mockMvc.perform(post("/api/authenticate").contentType(MediaType.APPLICATION_JSON).content(jsonString))
				.andExpect(status().isOk());
	}

	@Test
	void testBadRequest() throws Exception {
		this.mockMvc.perform(post("/api/authenticate")).andExpect(status().isBadRequest());
	}

	@Test
	void testExistingUserAuthenticate() throws Exception {
		User user = new User(1, "admin", "admin");
		UserDetails details = new org.springframework.security.core.userdetails.User(user.getUsername(),
				user.getPassword(), new ArrayList<>());
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
				"admin", "admin");
		when(authenticationManager.authenticate(new UsernamePasswordAuthenticationToken("admin", "admin")))
				.thenReturn(usernamePasswordAuthenticationToken);
		when(userDetailsService.loadUserByUsername("admin")).thenReturn(details);
		when(jwtAuthorizationUtil.getUsernameFromToken("token")).thenReturn("admin");
		when(jwtAuthorizationUtil.generateToken(details)).thenReturn("token");
		ObjectMapper mapper = new ObjectMapper();
		mockMvc.perform(MockMvcRequestBuilders.post("/api/authenticate").contentType(MediaType.APPLICATION_JSON)
				.content(mapper.writeValueAsString(new JwtRequest("admin", "admin")))).andExpect(status().isOk());
		

	}
	
	@Test
	void testUserClass() {
		User user = new User();
		user.setId(1);
		user.setUsername("admin");
		user.setPassword("admin");
		dao.save(user);
		when(dao.findByUsername(user.getUsername())).thenReturn(user);
		assertEquals(user.getId(), 1);
	}
	
	@Test
	void testResponseClas() {
		AuthorizationResponse authorizationResponse = new AuthorizationResponse();
		authorizationResponse.setMessage("create is sucess");
		authorizationResponse.setStatusCode(200);
		authorizationResponse.setToken("token");
		assertEquals(authorizationResponse.getStatusCode(),200);
	}
	
	@Test
	void testCustomUserDetails() {
		User user = new User();
		user.setId(1);
		user.setUsername("admin");
		user.setPassword("admin");
		CustomUserDetails details = new CustomUserDetails(user);
		assertThat(details.getAuthorities()).asString().contains("Admin");
		assertThat(details.getPassword()).asString().contains("admin");
		assertThat(details.getUsername()).asString().contains("admin");
		assertTrue(details.isAccountNonExpired());
		assertTrue(details.isAccountNonLocked());
		assertTrue(details.isCredentialsNonExpired());
		assertTrue(details.isEnabled());
	}
	
	@Test
	void testcreateAuthToken() {
		JwtAuthenticationController controller = new JwtAuthenticationController();
		JwtRequest jwtRequest= new JwtRequest("admin","admin");
		AuthorizationResponse authorizationResponse = new AuthorizationResponse();
		authorizationResponse.setMessage("Bad credentials");
		authorizationResponse.setStatusCode(400);
		authorizationResponse.setToken("");
		String data = authorizationResponse.toString();
		assertThat(controller.createAuthToken(jwtRequest)).hasToString(data);
		
	}

	@Test
	void testauthorizeRequest() {
		JwtAuthenticationController controller = new JwtAuthenticationController();
		AuthorizationResponse authorizationResponse = new AuthorizationResponse();
		authorizationResponse.setMessage("Not-Valid Token");
		authorizationResponse.setStatusCode(400);
		authorizationResponse.setToken("Not valid");
		String data = authorizationResponse.toString();
		assertThat(controller.authorizeRequest("token")).hasToString(data);
	}
	
	
}

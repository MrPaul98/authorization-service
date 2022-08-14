/**
 * 
 */
package com.pension.authorization.configuration;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.pension.authorization.service.JwtUserDetailsService;
/**
 * @author SAYANDIP PAUL
 *
 */
@Component
public class JwtAuthorizationFilter extends OncePerRequestFilter{

		@Autowired
		private JwtAuthorizationUtil jwtUtil;
		
		@Autowired
		private JwtUserDetailsService customerUserDetailsService;
		
		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
				throws ServletException, IOException {
			
			
			
			String requestTokenHeader = request.getHeader("Authorization");
			String username = null;
			String jwtToken = null;
			if(requestTokenHeader != null 
					&& requestTokenHeader.startsWith("Bearer ")) {
				 jwtToken = requestTokenHeader.substring(7);
				 try {
					username = this.jwtUtil.getUsernameFromToken(jwtToken);
				} catch (Exception e) {
				}
				 UserDetails userDetails = this.customerUserDetailsService.loadUserByUsername(username);
				 if(username!=null 
						 && SecurityContextHolder.getContext().getAuthentication()==null) {
					UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
					usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
					SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
				 }
				 
			}
			filterChain.doFilter(request, response);
		}

	

}

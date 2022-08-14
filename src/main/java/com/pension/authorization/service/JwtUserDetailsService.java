/**
 * 
 */
package com.pension.authorization.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.pension.authorization.model.CustomUserDetails;
import com.pension.authorization.model.User;
import com.pension.authorization.repository.UserDetailsDao;

/**
 * @author SAYANDIP PAUL
 *
 */
@Service
public class JwtUserDetailsService implements UserDetailsService{

	@Autowired
	private UserDetailsDao userDetailsDao;
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		final User user = userDetailsDao.findByUsername(username);
		if(user == null) {
			throw new UsernameNotFoundException("User not found");
		}
		return new CustomUserDetails(user);
	}

}

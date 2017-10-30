package com.trinary.security.auth;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.trinary.security.entities.User;
import com.trinary.security.token.Token;

public class TokenAuthentication implements Authentication {
	private static final long serialVersionUID = 1L;
	
	public User userDetails;
	public String tokenString;
	public Boolean authenticated;
	
	public TokenAuthentication(String tokenString) {
		this.userDetails = null;
		this.authenticated = false;
		this.tokenString = tokenString;
	}
	
	public TokenAuthentication(Token token) {
		this.userDetails = token.getPrincipal();
		this.authenticated = true;
		this.tokenString = token.getToken();
	}

	@Override
	public String getName() {
		return userDetails.getUsername();
	}

	@Override
	public Collection<GrantedAuthority> getAuthorities() {
		if (userDetails == null) {
			return Collections.emptyList();
		}
		
		return userDetails.getAuthorities();
	}

	@Override
	public Object getCredentials() {
		return tokenString;
	}

	@Override
	public Object getDetails() {
		return userDetails;
	}

	@Override
	public Object getPrincipal() {
		return userDetails;
	}
	
	public void setPrincipal(User userDetails) {
		this.userDetails = userDetails;
	}

	@Override
	public boolean isAuthenticated() {
		return authenticated;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated)
			throws IllegalArgumentException {
		this.authenticated = isAuthenticated;
	}
}
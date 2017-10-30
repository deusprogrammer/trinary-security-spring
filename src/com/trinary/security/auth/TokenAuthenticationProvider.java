package com.trinary.security.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import com.trinary.security.exceptions.TokenExpiredException;
import com.trinary.security.exceptions.TokenInvalidException;
import com.trinary.security.token.Token;
import com.trinary.security.token.TokenManager;

public class TokenAuthenticationProvider implements AuthenticationProvider {
	@Autowired TokenManager tokenManager;
	
	@Override
	public Authentication authenticate(Authentication auth)
			throws AuthenticationException {
		Token token;
		try {
			token = tokenManager.authenticateToken((String)auth.getCredentials());
		} catch (TokenInvalidException | TokenExpiredException e) {
			return auth;
		}
		
		TokenAuthentication newAuth = new TokenAuthentication(token);
		
		return newAuth;
	}

	@Override
	public boolean supports(Class<? extends Object> authClass) {
		return TokenAuthentication.class.isAssignableFrom(authClass);
	}

}

package com.trinary.security.token;

import org.springframework.beans.factory.annotation.Autowired;

import com.trinary.security.entities.User;
import com.trinary.security.exceptions.TokenExpiredException;
import com.trinary.security.exceptions.TokenInvalidException;
import org.springframework.stereotype.Component;

@Component
public abstract class TokenManager {
	@Autowired
	protected TokenFactory tokenFactory;
	
	protected abstract Token getTokenByString(String tokenString);
	protected abstract Token getTokenByPrincipal(User principal);
	protected abstract void storeToken(Token token);
	protected abstract Token releaseToken(Token token);
	
	public TokenManager() {}
	
	public TokenManager(TokenFactory tokenFactory) {
		this.tokenFactory = tokenFactory;
	}
	
	public Token createToken(User principal) {
		Token token = getTokenByPrincipal(principal);
		
		if (token == null || token.isExpired()) {
			token = tokenFactory.generateToken(principal);
		}
		
		storeToken(token);
		
		return token;
	}
	
	public Token authenticateToken(String tokenString) throws TokenInvalidException, TokenExpiredException {
		Token token = getTokenByString(tokenString);
		
		if (token == null) {
			throw new TokenInvalidException("Access is denied.  Token is invalid.");
		}
		
		if (token.isExpired()){
			throw new TokenExpiredException("Access is denied.  Token is expired.");
		}
		
		return token;
	}
	
	public Token releaseToken(String tokenString) {
		Token token = getTokenByString(tokenString);
		
		if (token == null) {
			return null;
		}
		
		return releaseToken(token);
	}
}
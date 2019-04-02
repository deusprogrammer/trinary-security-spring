package com.trinary.security;

import java.io.IOException;
import java.util.Collections;
import java.util.logging.Logger;

import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;
import org.springframework.web.filter.GenericFilterBean;

import com.trinary.security.auth.TokenAuthentication;
import com.trinary.security.entities.User;
import com.trinary.security.exceptions.TokenExpiredException;
import com.trinary.security.exceptions.TokenInvalidException;
import com.trinary.security.token.Token;
import com.trinary.security.token.TokenManager;

@Component
public class TokenBasedAuthenticationFilter extends GenericFilterBean {
	@Autowired 
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private TokenManager manager;
	
	private Authentication emptyAuth = createEmptyAuthentication();

	Logger LOGGER = Logger.getLogger(TokenBasedAuthenticationFilter.class.getSimpleName());

	@PostConstruct
	public void init() {
		SpringBeanAutowiringSupport.processInjectionBasedOnCurrentContext(this);
	}

	public TokenBasedAuthenticationFilter() {}

	public TokenBasedAuthenticationFilter(AuthenticationManager authenticationManager, TokenManager tokenManager) {
		this.authenticationManager = authenticationManager;
		this.manager = tokenManager;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain next)
			throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		
		String authHeader = httpRequest.getHeader("Authorization");
		if (authHeader == null) {
			SecurityContextHolder.getContext().setAuthentication(emptyAuth);
			next.doFilter(request, response);
			return;
		}
		
		String[] authHeaderParts = authHeader.split(" ");
		
		if (!authHeaderParts[0].trim().equals("Bearer")) {
			SecurityContextHolder.getContext().setAuthentication(emptyAuth);
			next.doFilter(request, response);
			return;
		}

		LOGGER.warning("TOKEN MANAGER: " + manager);
		LOGGER.warning("AUTH MANAGER:  " + authenticationManager);
		
		Token token = null;
		try {
			token = manager.authenticateToken(authHeaderParts[1]);
		} catch (TokenInvalidException | TokenExpiredException e) {
			e.printStackTrace();
		}
		
		if (token != null) {
			Authentication auth = authenticationManager.authenticate(new TokenAuthentication(token));
			SecurityContextHolder.getContext().setAuthentication(auth);
			
			next.doFilter(request, response);
			return;
		} else {
			SecurityContextHolder.getContext().setAuthentication(emptyAuth);
			next.doFilter(request, response);
			return;
		}
	}
	
	public Authentication createEmptyAuthentication() {
		User user = new User();
		user.setUsername("anonymous");
		user.setRoles(Collections.emptyList());
		user.setPassword("");
		TokenAuthentication auth = new TokenAuthentication("");
		auth.setAuthenticated(false);
		auth.setPrincipal(user);
		
		return auth;
	}
}
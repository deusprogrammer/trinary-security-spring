package com.trinary.security.token;

import com.trinary.security.entities.User;
import org.springframework.stereotype.Component;

@Component
public abstract class TokenFactory {
	public abstract Token generateToken(User principal);
}
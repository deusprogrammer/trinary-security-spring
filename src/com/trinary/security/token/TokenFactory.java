package com.trinary.security.token;

import com.trinary.security.entities.User;

public abstract class TokenFactory {
	public abstract Token generateToken(User principal);
}
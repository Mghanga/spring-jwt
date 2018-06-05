package com.jwt.services;

import com.jwt.models.Users;
import com.jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
public class AppUserDetailsService implements UserDetailsService {

    @Autowired private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
        Optional<Users> oUser = userRepository.findByUsername( username );

        // If the user was not found, throw an exception
        if( !oUser.isPresent() ) throw new UsernameNotFoundException("The username '" + username + "' was not found");

        Users entity = oUser.get();
        return new User( entity.getUsername(), entity.getPassword(), Collections.emptySet() );
    }
}

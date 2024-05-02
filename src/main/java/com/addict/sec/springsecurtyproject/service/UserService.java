package com.addict.sec.springsecurtyproject.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.addict.sec.springsecurtyproject.repository.UserRepository;


@Service
public class UserService implements UserDetailsService{
    
    @Autowired
    private UserRepository repo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       return repo.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException(username));
    }
    
    
}

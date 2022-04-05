package ru.tweekyone.resourceserver.service;

import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import ru.tweekyone.resourceserver.domain.UserDetailsImpl;
import ru.tweekyone.resourceserver.repository.UserRepository;

import javax.transaction.Transactional;
import java.util.Set;

@Service
@Transactional
@AllArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetailsImpl userDetails = userRepository.findByName(username)
                .map(u -> new UserDetailsImpl(
                        u.getName(),
                        u.getPassword(),
                        Set.of(u.getRole()),
                        u.isEnabled()
                )).orElseThrow(() -> new UsernameNotFoundException(
                        String.format("User with %s not found!", username)
                ));
        return userDetails;
    }
}

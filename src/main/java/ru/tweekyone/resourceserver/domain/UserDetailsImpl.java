package ru.tweekyone.resourceserver.domain;

import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import ru.tweekyone.resourceserver.entity.Role;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@AllArgsConstructor
public class UserDetailsImpl implements UserDetails {
    private String username;
    private String password;
    private Set<Role> roles;
    private boolean isEnable;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(r -> new GrantedAuthority() {
            @Override
            public String getAuthority() {
                return r.getRole();
            }
        })
                .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return isEnable;
    }

    @Override
    public boolean isAccountNonLocked() {
        return isEnable;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return isEnable;
    }

    @Override
    public boolean isEnabled() {
        return isEnable;
    }
}

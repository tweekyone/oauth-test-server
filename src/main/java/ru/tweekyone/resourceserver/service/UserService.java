package ru.tweekyone.resourceserver.service;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import ru.tweekyone.resourceserver.dto.UserDto;
import ru.tweekyone.resourceserver.entity.User;
import ru.tweekyone.resourceserver.exceptions.UserNotFoundException;
import ru.tweekyone.resourceserver.repository.UserRepository;

import javax.transaction.Transactional;

@Service
@Transactional
@AllArgsConstructor
public class UserService {

    private UserRepository userRepository;

    public UserDto getUserById(Long id) {
        User result = userRepository.findById(id).orElseThrow(() -> new UserNotFoundException());
        return new UserDto(
                result.getId(),
                result.getName(),
                result.getRole().getRole()
        );
    }
}

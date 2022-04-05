package ru.tweekyone.resourceserver.controller;

import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.tweekyone.resourceserver.dto.UserDto;
import ru.tweekyone.resourceserver.entity.User;
import ru.tweekyone.resourceserver.service.UserService;

@RestController
@RequestMapping("/users")
@AllArgsConstructor
public class TestController {

    private UserService userService;

    @GetMapping("/{userId}")
    public ResponseEntity<UserDto> getUserById(@PathVariable("userId") Long id) {
        UserDto result = userService.getUserById(id);
        return new ResponseEntity<>(result, HttpStatus.OK);
    }
}

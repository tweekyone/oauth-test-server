package ru.tweekyone.resourceserver.exceptions;

public class UserNotFoundException extends RuntimeException{
    public UserNotFoundException() {
        super("User not found!");
    }
}

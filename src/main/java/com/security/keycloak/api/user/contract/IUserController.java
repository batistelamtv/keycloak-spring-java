package com.security.keycloak.api.user.contract;

import com.security.keycloak.dto.user.CreateUserRequest;
import com.security.keycloak.dto.user.UserResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;


import java.util.List;

public interface IUserController {

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    Object save(@RequestBody @Valid CreateUserRequest createUserRequest);

    @GetMapping("roles")
    List<String> getRoles();

    @PatchMapping("/senha/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void resetSenha(@PathVariable("id") String id, @RequestParam String senha);

    @GetMapping("/findAll")
    List<UserResponse> findAll();

    @DeleteMapping("{userId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void deleteUserPorId(@PathVariable("userId") String userId);

    @GetMapping("/login")
    Object login(@RequestParam String login, @RequestParam String password);

    @GetMapping("/find-by-email")
    UserResponse getByEmail(@RequestParam String email);
}

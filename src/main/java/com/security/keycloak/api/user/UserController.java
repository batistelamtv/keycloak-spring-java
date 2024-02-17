package com.security.keycloak.api.user;

import com.security.keycloak.api.user.contract.IUserController;
import com.security.keycloak.dto.user.CreateUserRequest;
import com.security.keycloak.dto.user.UserResponse;
import com.security.keycloak.service.KeycloakService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/v1/users")
@RequiredArgsConstructor
public class UserController implements IUserController {

    private final KeycloakService keycloakService;

    @Override
    public Object save(CreateUserRequest createUserRequest) {
        return keycloakService.saveUser(createUserRequest);
    }

    @Override
    public List<String> getRoles() {
        return keycloakService.getRoles();
    }

    @Override
    public void resetSenha(String id, String senha) {
        keycloakService.updateSenha(id, senha);
    }

    @Override
    public List<UserResponse> findAll() {
        return keycloakService.findAll();
    }

    @Override
    public void deleteUserPorId(String userId) {
        keycloakService.deletePorId(userId);
    }

    @Override
    public Object login(String login, String password) {
        return keycloakService.getToken(login, password);
    }

    @Override
    public UserResponse getByEmail(String email) {
        return keycloakService.findByLoginEndpoint(email);
    }
}

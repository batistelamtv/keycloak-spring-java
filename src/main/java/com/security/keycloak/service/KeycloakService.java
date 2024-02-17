package com.security.keycloak.service;

import com.security.keycloak.domain.exception.NaoEncontradoException;
import com.security.keycloak.dto.user.CreateUserRequest;
import com.security.keycloak.dto.user.UserResponse;
import jakarta.ws.rs.NotAuthorizedException;
import lombok.RequiredArgsConstructor;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;

import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.ObjectUtils;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class KeycloakService {

    private final Keycloak keycloak;

    @Value("${keycloak.url}")
    private String serverUrl;
    @Value("${keycloak.realm}")
    private String realm;
    @Value("${keycloak.clientId}")
    private String clientIdLogin;

    @Value("${keycloak.clientSecret}")
    private String clientSecret;

    public Object getToken(String userName, String password) {

        Keycloak keycloakf = KeycloakBuilder.builder() //
                .serverUrl(serverUrl) //
                .realm(realm) //
                .grantType(OAuth2Constants.PASSWORD) //z`
                .clientId(clientIdLogin) //
                .clientSecret(clientSecret)
                .username(userName) //
                .password(password) //
                .build();
        try {
            return keycloakf.tokenManager().getAccessToken();
        } catch (Exception ex) {
            if (ex.getMessage().contains("Unauthorized"))
                throw new NotAuthorizedException("");

            throw new RuntimeException(ex);
        }
    }

    public Object saveUser(CreateUserRequest createUserRequest) {

        var senhaCredenetial = criarCredencial(createUserRequest.getSenha());
        RealmResource realmResource = keycloak.realm(realm);
        UsersResource userRessource = realmResource.users();

        var user = criarUsuario(createUserRequest, senhaCredenetial);
        var response = userRessource.create(user);

        if (response.getStatusInfo().getStatusCode() == 201) {
            var createdUer = findByLogin(createUserRequest.getEmail());
            setRole(createdUer.getId(), createUserRequest.getRoleName());
        }
        return response.getStatusInfo();
    }

    public void updateSenha(String login, String novaSenha) {
        RealmResource realmResource = keycloak.realm(realm);
        var user = realmResource.users().get(login);
        var userR = user.toRepresentation();
        var novaCredencial = criarCredencial(novaSenha);
        userR.setCredentials(List.of(novaCredencial));
        user.update(userR);
    }

    public List<UserResponse> findAll() {
        return keycloak.realm(realm).users().list()
                .stream()
                .map(userRepresentation -> {
                    var user = new UserResponse();
                    BeanUtils.copyProperties(userRepresentation, user);
                    user.setRoles(getUserRoles(user.getId()));
                    return user;
                })
                .collect(Collectors.toList());
    }

    private List<String> getUserRoles(String id) {
        return keycloak.realm(realm).users().get(id).roles().realmLevel().listAll().stream()
                .map(RoleRepresentation::getName)
                .collect(Collectors.toList());
    }

    private void setRole(String userId, String roleName) {
        RealmResource realmResource = keycloak.realm(realm);
        var role = getRoleOuThrow(roleName);
        realmResource.users().get(userId).roles().realmLevel().add(List.of(role));
    }

    private UserRepresentation findByLogin(String login) {
        RealmResource realmResource = keycloak.realm(realm);
        return realmResource.users().search(login).get(0);
    }

    public UserResponse findByLoginEndpoint(String login) {
        RealmResource realmResource = keycloak.realm(realm);
        var response = realmResource.users().search(login).get(0);

        if (ObjectUtils.isEmpty(response)) {
            throw new NaoEncontradoException("Usuário não encontrado.");
        }
        var user = new UserResponse();
        BeanUtils.copyProperties(response, user);
        user.setRoles(getUserRoles(user.getId()));
        return user;

    }

    private CredentialRepresentation criarCredencial(final String senha) {
        var credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setTemporary(Boolean.FALSE);
        credential.setValue(senha);
        return credential;
    }

    private UserRepresentation criarUsuario(final CreateUserRequest createUserRequest, final CredentialRepresentation credentialRepresentation) {
        var user = new UserRepresentation();
        user.setEnabled(true);
        user.setUsername(createUserRequest.getEmail());
        user.setFirstName(createUserRequest.getNome());
        user.setLastName(createUserRequest.getSobrenome());
        user.setEmail(createUserRequest.getEmail());
        user.setEmailVerified(Boolean.FALSE);
        user.setCredentials(List.of(credentialRepresentation));
        return user;
    }

    private RoleRepresentation getRoleOuThrow(String roleName) {
        RealmResource realmResource = keycloak.realm(realm);
        return Optional.ofNullable(realmResource.roles().get(roleName).toRepresentation())
                .orElseThrow(() -> new NaoEncontradoException("Role não encontrado."));
    }

    public List<String> getRoles() {
        return keycloak.realm(realm)
                .roles()
                .list()
                .stream()
                .map(RoleRepresentation::getName)
                .collect(Collectors.toList());
    }

    public void deletePorId(String userId) {
        keycloak.realm(realm).users().delete(userId);
    }
}

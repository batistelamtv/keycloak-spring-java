package com.security.keycloak.api.user;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/produtos")
@RequiredArgsConstructor
public class CidadeController {


    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminString() {
        return "admin teste";
    }

    @GetMapping("/operation")
    public String operationString() {
        return "operation teste";
    }
}

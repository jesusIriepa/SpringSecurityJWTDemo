package com.example.demo.rest;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class TestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void should_return_401_access_without_authorization_token() throws Exception {
        mockMvc.perform(
                get("/test/user"))
            .andDo(print())
            .andExpect(status().isUnauthorized());
    }

    @Test
    void should_return_403_access_without_mandatory_rol() throws Exception {
        String authToken = loginUser();
        mockMvc.perform(
                get("/test/admin")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + authToken))
            .andDo(print())
            .andExpect(status().isForbidden());
    }

    @Test
    void should_access_user_ok() throws Exception {
        String authToken = loginUser();
        mockMvc.perform(
                get("/test/user")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + authToken))
            .andDo(print())
            .andExpect(status().isOk());

    }

    private String loginUser() throws Exception {
        MvcResult loginResponse = mockMvc.perform(
                post("/login")
                    .param("username", "user")
                    .param("password", "password")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED))
            .andDo(print())
            .andExpect(status().isOk())
            .andReturn();
        return loginResponse.getResponse().getHeader(HttpHeaders.AUTHORIZATION);
    }


}
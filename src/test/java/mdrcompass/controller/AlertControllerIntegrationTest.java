package mdrcompass.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import mdrcompass.model.Alert;
import mdrcompass.repository.AlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class AlertControllerIntegrationTest {

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16");

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("app.username", () -> "testuser");
        registry.add("app.password", () -> "testpass");
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AlertRepository alertRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        alertRepository.deleteAll();
    }

    private Alert createTestAlert() {
        Alert alert = new Alert();
        alert.setName("DNS Tunneling");
        alert.setDescription("DNS Tunneling detection");
        alert.setKillChain("Command and Control");
        alert.setMitreId("T1071.004");
        return alert;
    }

    @Test
    @WithMockUser
    void createAndGetAlert() throws Exception {
        String json = objectMapper.writeValueAsString(createTestAlert());

        String response = mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("DNS Tunneling"))
                .andExpect(jsonPath("$.id").exists())
                .andReturn().getResponse().getContentAsString();

        Alert created = objectMapper.readValue(response, Alert.class);

        mockMvc.perform(get("/api/alerts/" + created.getId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("DNS Tunneling"));
    }

    @Test
    @WithMockUser
    void getAllAlerts() throws Exception {
        String json1 = objectMapper.writeValueAsString(createTestAlert());

        Alert alert2 = createTestAlert();
        alert2.setName("Kerberoasting");
        String json2 = objectMapper.writeValueAsString(alert2);

        mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json1))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json2))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));
    }

    @Test
    @WithMockUser
    void updateAlert() throws Exception {
        String json = objectMapper.writeValueAsString(createTestAlert());

        String response = mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        Alert created = objectMapper.readValue(response, Alert.class);
        created.setName("Updated Alert");
        String updatedJson = objectMapper.writeValueAsString(created);

        mockMvc.perform(put("/api/alerts/" + created.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(updatedJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Updated Alert"));
    }

    @Test
    @WithMockUser
    void deleteAlert() throws Exception {
        String json = objectMapper.writeValueAsString(createTestAlert());

        String response = mockMvc.perform(post("/api/alerts")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();

        Alert created = objectMapper.readValue(response, Alert.class);

        mockMvc.perform(delete("/api/alerts/" + created.getId()))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/alerts/" + created.getId()))
                .andExpect(status().isNotFound());
    }

    @Test
    @WithMockUser
    void getAlertNotFound() throws Exception {
        mockMvc.perform(get("/api/alerts/999"))
                .andExpect(status().isNotFound());
    }

    @Test
    void unauthenticatedRequestIsRejected() throws Exception {
        mockMvc.perform(get("/api/alerts"))
                .andExpect(status().isForbidden());
    }
}
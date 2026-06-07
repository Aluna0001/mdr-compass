package mdrcompass.service;

import mdrcompass.model.Alert;
import mdrcompass.repository.AlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AlertServiceTest {

    @Mock
    private AlertRepository alertRepository;

    @InjectMocks
    private AlertService alertService;

    private Alert testAlert;

    @BeforeEach
    void setUp() {
        testAlert = new Alert();
        testAlert.setName("DNS Tunneling");
        testAlert.setDescription("DNS Tunneling detection");
        testAlert.setKillChain("Command and Control");
        testAlert.setMitreId("T1071.004");
    }

    @Test
    void getAllAlerts_returnsList() {
        when(alertRepository.findAll()).thenReturn(List.of(testAlert));

        List<Alert> result = alertService.getAllAlerts();

        assertEquals(1, result.size());
        assertEquals("DNS Tunneling", result.get(0).getName());
        verify(alertRepository).findAll();
    }

    @Test
    void getAllAlerts_returnsEmptyList() {
        when(alertRepository.findAll()).thenReturn(Collections.emptyList());

        List<Alert> result = alertService.getAllAlerts();

        assertTrue(result.isEmpty());
        verify(alertRepository).findAll();
    }

    @Test
    void getAlertById_returnsAlert() {
        when(alertRepository.findById(1L)).thenReturn(Optional.of(testAlert));

        Alert result = alertService.getAlertById(1L);

        assertEquals("DNS Tunneling", result.getName());
        verify(alertRepository).findById(1L);
    }

    @Test
    void getAlertById_throwsWhenNotFound() {
        when(alertRepository.findById(99L)).thenReturn(Optional.empty());

        assertThrows(ResponseStatusException.class,
                () -> alertService.getAlertById(99L));
        verify(alertRepository).findById(99L);
    }

    @Test
    void searchAlerts_returnsMatchingAlerts() {
        when(alertRepository.findByNameContainingIgnoreCase("DNS"))
                .thenReturn(List.of(testAlert));

        List<Alert> result = alertService.searchAlerts("DNS");

        assertEquals(1, result.size());
        assertEquals("DNS Tunneling", result.get(0).getName());
        verify(alertRepository).findByNameContainingIgnoreCase("DNS");
    }

    @Test
    void searchAlerts_returnsEmptyWhenNoMatch() {
        when(alertRepository.findByNameContainingIgnoreCase("XYZ"))
                .thenReturn(Collections.emptyList());

        List<Alert> result = alertService.searchAlerts("XYZ");

        assertTrue(result.isEmpty());
        verify(alertRepository).findByNameContainingIgnoreCase("XYZ");
    }

    @Test
    void createAlert_savesAndReturns() {
        when(alertRepository.save(testAlert)).thenReturn(testAlert);

        Alert result = alertService.createAlert(testAlert);

        assertEquals("DNS Tunneling", result.getName());
        verify(alertRepository).save(testAlert);
    }

    @Test
    void updateAlert_updatesWhenExists() {
        when(alertRepository.existsById(1L)).thenReturn(true);
        when(alertRepository.save(testAlert)).thenReturn(testAlert);

        Alert result = alertService.updateAlert(1L, testAlert);

        assertEquals("DNS Tunneling", result.getName());
        verify(alertRepository).existsById(1L);
        verify(alertRepository).save(testAlert);
    }

    @Test
    void updateAlert_throwsWhenNotFound() {
        when(alertRepository.existsById(99L)).thenReturn(false);

        assertThrows(ResponseStatusException.class,
                () -> alertService.updateAlert(99L, testAlert));
        verify(alertRepository).existsById(99L);
        verify(alertRepository, never()).save(any());
    }

    @Test
    void deleteAlert_deletesWhenExists() {
        when(alertRepository.existsById(1L)).thenReturn(true);

        alertService.deleteAlert(1L);

        verify(alertRepository).existsById(1L);
        verify(alertRepository).deleteById(1L);
    }

    @Test
    void deleteAlert_throwsWhenNotFound() {
        when(alertRepository.existsById(99L)).thenReturn(false);

        assertThrows(ResponseStatusException.class,
                () -> alertService.deleteAlert(99L));
        verify(alertRepository).existsById(99L);
        verify(alertRepository, never()).deleteById(any());
    }
}
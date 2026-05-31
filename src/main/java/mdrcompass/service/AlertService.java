package mdrcompass.service;

import mdrcompass.model.Alert;
import mdrcompass.repository.AlertRepository;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.util.List;

@Service
public class AlertService {

    private final AlertRepository alertRepository;

    public AlertService(AlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    public List<Alert> getAllAlerts() {
        return alertRepository.findAll();
    }

    public Alert getAlertById(Long id) {
        return alertRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Alert not found with id: " + id));
    }

    public List<Alert> searchAlerts(String name) {
        return alertRepository.findByNameContainingIgnoreCase(name);
    }

    public Alert createAlert(Alert alert) {
        return alertRepository.save(alert);
    }

    public Alert updateAlert(Long id, Alert alert) {
        if (!alertRepository.existsById(id)) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "Alert not found with id: " + id);
        }
        return alertRepository.save(alert);
    }

    public void deleteAlert(Long id) {
        if (!alertRepository.existsById(id)) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "Alert not found with id: " + id);
        }
        alertRepository.deleteById(id);
    }
}
package mdrcompass.controller;

import mdrcompass.model.Alert;
import mdrcompass.repository.AlertRepository;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertRepository alertRepository;

    public AlertController(AlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    @GetMapping
    public List<Alert> getAlerts() {
        return alertRepository.findAll();
    }

    @GetMapping("/{id}")
    public Alert getAlertById(@PathVariable Long id) {
        return alertRepository.findById(id).orElse(null);
    }

    @GetMapping("/search")
    public List<Alert> searchAlerts(@RequestParam String name) {
        return alertRepository.findByNameContainingIgnoreCase(name);
    }
}
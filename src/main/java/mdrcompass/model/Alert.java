package mdrcompass.model;

import jakarta.persistence.*;
import java.util.List;

@Entity
@Table(name = "alerts")
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;

    @Column(columnDefinition = "TEXT")
    private String description;

    private String killChain;
    private String mitreId;

    @ElementCollection
    @CollectionTable(name = "alert_indicators", joinColumns = @JoinColumn(name = "alert_id"))
    @Column(name = "indicator")
    private List<String> suspiciousIndicators;

    @ElementCollection
    @CollectionTable(name = "alert_hints", joinColumns = @JoinColumn(name = "alert_id"))
    private List<WhatToLookFor> whatToLookFor;

    @ElementCollection
    @CollectionTable(name = "alert_processes", joinColumns = @JoinColumn(name = "alert_id"))
    private List<RelatedProcess> relatedProcesses;

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getKillChain() {
        return killChain;
    }

    public void setKillChain(String killChain) {
        this.killChain = killChain;
    }

    public String getMitreId() {
        return mitreId;
    }

    public void setMitreId(String mitreId) {
        this.mitreId = mitreId;
    }

    public List<String> getSuspiciousIndicators() {
        return suspiciousIndicators;
    }

    public void setSuspiciousIndicators(List<String> suspiciousIndicators) {
        this.suspiciousIndicators = suspiciousIndicators;
    }

    public List<WhatToLookFor> getWhatToLookFor() {
        return whatToLookFor;
    }
    public void setWhatToLookFor(List<WhatToLookFor> whatToLookFor) {
        this.whatToLookFor = whatToLookFor;
    }

    public List<RelatedProcess> getRelatedProcesses() {
        return relatedProcesses;
    }

    public void setRelatedProcesses(List<RelatedProcess> relatedProcesses) {
        this.relatedProcesses = relatedProcesses;
    }
}
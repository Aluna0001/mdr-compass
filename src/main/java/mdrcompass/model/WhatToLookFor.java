package mdrcompass.model;

import jakarta.persistence.Embeddable;

@Embeddable
public class WhatToLookFor {

    private String label;
    private String question;

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getQuestion() {
        return question;
    }

    public void setQuestion(String question) {
        this.question = question;
    }
}
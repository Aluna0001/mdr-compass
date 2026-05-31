package mdrcompass.model;

import jakarta.persistence.Embeddable;

@Embeddable
public class RelatedProcess {

    private String name;
    private String legitimatePath;
    private String suspiciousPath;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLegittimatePath() {
        return legitimatePath;
    }

    public void setLegittimatePath(String legitimatePath) {
        this.legitimatePath = legitimatePath;
    }

    public String getSuspiciousPath() {
        return suspiciousPath;
    }

    public void setSuspiciousPath(String suspiciousPath) {
        this.suspiciousPath = suspiciousPath;
    }
}
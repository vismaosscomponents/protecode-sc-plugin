package com.synopsys.protecode.sc.jenkins;

import com.google.common.collect.ImmutableSet;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import java.util.Set;

public class ProtecodeScanStep extends Step {

    private String protecodeScGroup;
    private String credentialsId;
    private String artifactDir;
    private String artifactsFilter;
    private boolean scanAllArchivedArtifacts;
    private boolean convertToSummary;
    private boolean failIfVulns;
    private boolean leaveArtifacts;

    private int scanTimeout = 10;

    @DataBoundConstructor
    public ProtecodeScanStep(String protecodeScGroup, String credentialsId, boolean scanAllArchivedArtifacts, String artifactDir) {
        this.scanAllArchivedArtifacts = scanAllArchivedArtifacts;
        this.protecodeScGroup = protecodeScGroup;
        this.artifactDir = artifactDir;
        this.credentialsId = credentialsId;
    }

    public String getArtifactDir() {
        return artifactDir;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    public String getProtecodeScGroup() {
        return protecodeScGroup;
    }

    public boolean isScanAllArchivedArtifacts() {
        return scanAllArchivedArtifacts;
    }

    public boolean isConvertToSummary() {
        return convertToSummary;
    }

    @DataBoundSetter
    public void setConvertToSummary(boolean convertToSummary) {
        this.convertToSummary = convertToSummary;
    }

    public boolean isFailIfVulns() {
        return failIfVulns;
    }

    @DataBoundSetter
    public void setFailIfVulns(boolean failIfVulns) {
        this.failIfVulns = failIfVulns;
    }

    public boolean isLeaveArtifacts() {
        return leaveArtifacts;
    }

    @DataBoundSetter
    public void setLeaveArtifacts(boolean leaveArtifacts) {
        this.leaveArtifacts = leaveArtifacts;
    }

    public int getScanTimeout() {
        return scanTimeout;
    }

    @DataBoundSetter
    public void setScanTimeout(int scanTimeout) {
        this.scanTimeout = scanTimeout;
    }


    public String getArtifactsFilter() {
        return artifactsFilter;
    }

    @DataBoundSetter
    public void setArtifactsFilter(String artifactsFilter) {
        this.artifactsFilter = artifactsFilter;
    }

    @Override
    public StepExecution start(StepContext context) throws Exception {
        return new ProtecodeScanStepExecutor(this, context);
    }

    @Extension
    public static class ProtecodeScanStepDescriptor extends StepDescriptor {

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return ImmutableSet.of(FilePath.class, Run.class, Launcher.class, TaskListener.class);
        }

        @Override
        public String getFunctionName() {
            return "protecodeScan";
        }

        @Override
        public String getDisplayName() {
            return "Protecode scan";
        }
    }
}

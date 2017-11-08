/*******************************************************************************
 * Copyright (c) 2016 Synopsys, Inc
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *    Synopsys, Inc - initial implementation and documentation
 *******************************************************************************/

package com.synopsys.protecode.sc.jenkins;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.common.StandardUsernameListBoxModel;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.cloudbees.plugins.credentials.domains.HostnameRequirement;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.FilePath;
import hudson.FilePath.FileCallable;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Item;
import hudson.model.Run;
import hudson.remoting.VirtualChannel;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.ListBoxModel;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.remoting.RoleChecker;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ProtecodeScIntegrator extends Notifier {

    private String protecodeScGroup;
    private String credentialsId;
    private String artifactDir;
    private boolean convertToSummary = true;
    private boolean failIfVulns;
    private boolean leaveArtifacts;
    private int scanTimeout;

    @DataBoundConstructor
    public ProtecodeScIntegrator(String credentialsId, String protecodeScGroup,
                                 boolean failIfVulns, String artifactDir, boolean convertToSummary,
                                 boolean leaveArtifacts, int scanTimeout) {
        this.credentialsId = credentialsId;
        this.protecodeScGroup = protecodeScGroup;
        this.artifactDir = artifactDir;
        this.convertToSummary = convertToSummary;
        this.failIfVulns = failIfVulns;
        this.leaveArtifacts = leaveArtifacts;
        this.scanTimeout = scanTimeout > 60 ? scanTimeout : 60;
    }

    public String getProtecodeScGroup() {
        return protecodeScGroup;
    }

    public String getCredentialsId() {
        return credentialsId;
    }

    public String getArtifactDir() {
        return artifactDir;
    }

    public int getScanTimeout() {
        return scanTimeout;
    }

    public boolean isConvertToSummary() {
        return convertToSummary;
    }

    public boolean isFailIfVulns() {
        return failIfVulns;
    }

    public boolean isLeaveArtifacts() {
        return leaveArtifacts;
    }


    @Override
    public boolean prebuild(AbstractBuild<?, ?> build, BuildListener listener) {
        if (getDescriptor().getProtecodeScHost() == null) {
            listener.error(
                    "Protecode SC host not defined. Configure it to global plugin properties");
            return false;
        }

        return true;
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
    @Override
    public boolean perform(AbstractBuild<?, ?> build, Launcher launcher,
                           BuildListener listener) throws InterruptedException, IOException {
        PrintStream log = listener.getLogger();

        ProtecodeScanRunner runner = new ProtecodeScanRunner(getDescriptor(), credentialsId, protecodeScGroup,
                artifactDir, scanTimeout, convertToSummary, leaveArtifacts
                , failIfVulns);
        return runner.perform(new BuildInformationAdapter(build),
                new MyArtifactsProvider(build, log, artifactDir),
                listener.getLogger());
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return new DescriptorImpl();
    }

    @SuppressWarnings("serial")
    private static final class FileReader implements FileCallable<File> {

        @Override
        public void checkRoles(RoleChecker arg0) throws SecurityException {
            // intentionally left empty
        }

        @Override
        public File invoke(File f, VirtualChannel channel)
                throws IOException, InterruptedException {
            return f.getAbsoluteFile();
        }

    }

    public static final class MyArtifactsProvider implements ArtifactsProvider {
        private final AbstractBuild<?, ?> build;
        private final PrintStream log;
        private final String artifactDir;

        public MyArtifactsProvider(AbstractBuild<?, ?> build, PrintStream log, String artifactDir) {
            this.build = build;
            this.log = log;
            this.artifactDir = artifactDir;
        }

        @Override
        public List<Artifact> getArtifacts() throws IOException, InterruptedException {
            List<Artifact> artifacts = new ArrayList<>();
            if (!StringUtils.isEmpty(artifactDir)) {
                List<FilePath> files = build.getWorkspace().child(artifactDir)
                        .list(new ScanFileFilter());
                if (files != null) {
                    for (FilePath file : files) {
                        artifacts.add(new Artifact(file));
                        log.println("Adding file " + file.getName()
                                + " for Protecode SC scan");
                    }
                } else {
                    log.println(String.format("Could not get additional artifacts from %s", artifactDir));
                }
            }

            List<? extends Run<?, ?>.Artifact> buildArtifacts = build
                    .getArtifacts();
            for (Run<?, ?>.Artifact buildArtifact : buildArtifacts) {
                artifacts.add(new Artifact(buildArtifact.getFile()));
            }

            return artifacts;
        }
    }

    public static final class BuildInformationAdapter implements BuildInformation {

        private final AbstractBuild<?, ?> build;

        public BuildInformationAdapter(AbstractBuild<?, ?> build) {
            this.build = build;
        }

        @Override
        public File getArtifactsDir() {
            return build.getArtifactsDir();
        }

        @Override
        public FilePath getWorkspace() {
            return build.getWorkspace();
        }

        @Override
        public int getNumber() {
            return build.getNumber();
        }

        @Override
        public String getAbsoluteUrl() {
            return build.getAbsoluteUrl();
        }
    }

    // This indicates to Jenkins that this is an implementation of an extension
    // point.
    @Extension
    public static final class DescriptorImpl
            extends BuildStepDescriptor<Publisher> {

        private String protecodeScHost;
        private boolean dontCheckCert;

        public DescriptorImpl() {
            load();
        }

        @SuppressWarnings("rawtypes")
        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            // Indicates that this builder can be used with all kinds of project
            // types
            return true;
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject formData)
                throws FormException {
            // To persist global configuration information,
            // set that to properties and call save().
            protecodeScHost = formData.getString("protecodeScHost");
            dontCheckCert = formData.getBoolean("dontCheckCert");

            save();
            return super.configure(req, formData);
        }

        public ListBoxModel doFillCredentialsIdItems() {
            Item item = Stapler.getCurrentRequest().findAncestorObject(Item.class);
            return new StandardUsernameListBoxModel()
                    .includeEmptyValue()
                    .includeMatchingAs(
                            ACL.SYSTEM,
                            item,
                            StandardUsernamePasswordCredentials.class,
                            Collections.<DomainRequirement>singletonList(new HostnameRequirement(protecodeScHost)),
                            CredentialsMatchers.anyOf(CredentialsMatchers.instanceOf(
                                    StandardUsernamePasswordCredentials.class))
                    );
        }

        @Override
        public String getDisplayName() {
            return "Protecode SC";
        }

        public String getProtecodeScHost() {
            return protecodeScHost;
        }

        public boolean isDontCheckCert() {
            return dontCheckCert;
        }

    }

    @Override
    public BuildStepMonitor getRequiredMonitorService() {
        return BuildStepMonitor.BUILD;
    }

}

package com.synopsys.protecode.sc.jenkins;

import hudson.AbortException;
import hudson.FilePath;
import hudson.model.Run;
import hudson.model.TaskListener;
import org.apache.commons.io.filefilter.AndFileFilter;
import org.apache.commons.io.filefilter.FileFileFilter;
import org.apache.commons.io.filefilter.IOFileFilter;
import org.apache.commons.io.filefilter.WildcardFileFilter;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.SynchronousNonBlockingStepExecution;

import javax.annotation.Nonnull;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

public class ProtecodeScanStepExecutor extends SynchronousNonBlockingStepExecution<Void> implements ArtifactsProvider {

    private static final long serialVersionUID = 1L;

    private transient final ProtecodeScanStep protecodeScanStep;

    protected ProtecodeScanStepExecutor(@Nonnull ProtecodeScanStep protecodeScanStep, @Nonnull StepContext context) {
        super(context);
        this.protecodeScanStep = protecodeScanStep;
    }

    @Override
    protected Void run() throws Exception {
        ProtecodeScIntegrator.DescriptorImpl descriptor = new ProtecodeScIntegrator.DescriptorImpl();
        ProtecodeScanRunner protecodeScanRunner = new ProtecodeScanRunner(
                descriptor,
                protecodeScanStep.getCredentialsId(),
                protecodeScanStep.getProtecodeScGroup(),
                "",
                10,
                false,
                false,
                false);

        FilePath workspace = getContext().get(FilePath.class);
        TaskListener listener = getContext().get(TaskListener.class);
        Run run = getContext().get(Run.class);

        if (descriptor.getProtecodeScHost() == null) {
            listener.error("Protecode SC host not defined. Configure it to global plugin properties");
            throw new AbortException("Protecode configuration is invalid");
        }

        if (!protecodeScanRunner.perform(new BuildInformationAdapter(run, workspace), this, listener.getLogger())) {
            throw new AbortException("Vulnerabilities found");
        }
        return null;
    }

    @Override
    public List<Artifact> getArtifacts() throws IOException, InterruptedException {
        FilePath workspace = getContext().get(FilePath.class);
        PrintStream logger = getContext().get(TaskListener.class).getLogger();
        Run run = getContext().get(Run.class);

        IOFileFilter fileFilter = FileFileFilter.FILE;
        String artifactsFilter = protecodeScanStep.getArtifactsFilter();
        if (!StringUtils.isEmpty(artifactsFilter)) {
            fileFilter = new AndFileFilter(fileFilter, new WildcardFileFilter(artifactsFilter));
        }

        List<Artifact> artifacts = new ArrayList<>();
        if (!StringUtils.isEmpty(protecodeScanStep.getArtifactDir())) {
            List<FilePath> files = workspace.child(protecodeScanStep.getArtifactDir())
                    .list(fileFilter);
            if (files != null) {
                for (FilePath file : files) {
                    artifacts.add(new Artifact(file));
                    logger.println("Adding file " + file.getName()
                            + " for Protecode SC scan");
                }
            } else {
                logger.println(String.format("Could not get additional artifacts from %s", protecodeScanStep.getArtifactDir()));
            }
        }

        if (protecodeScanStep.isScanAllArchivedArtifacts()) {
            List<? extends Run<?, ?>.Artifact> buildArtifacts = run.getArtifacts();
            for (Run<?, ?>.Artifact buildArtifact : buildArtifacts) {
                File buildArtifactFile = buildArtifact.getFile();
                if (fileFilter.accept(buildArtifactFile)) {
                    artifacts.add(new Artifact(buildArtifactFile));
                    logger.println("Adding file " + buildArtifactFile.getName()
                            + " for Protecode SC scan");
                }
            }
        }
        return artifacts;
    }

    private final static class BuildInformationAdapter implements BuildInformation {
        private final Run run;
        private final FilePath workspace;

        public BuildInformationAdapter(Run run, FilePath workspace) {
            this.run = run;
            this.workspace = workspace;
        }

        @Override
        public File getArtifactsDir() {
            return run.getArtifactsDir();
        }

        @Override
        public FilePath getWorkspace() {
            return workspace;
        }

        @Override
        public int getNumber() {
            return run.getNumber();
        }

        @Override
        public String getAbsoluteUrl() {
            return run.getAbsoluteUrl();
        }
    }
}

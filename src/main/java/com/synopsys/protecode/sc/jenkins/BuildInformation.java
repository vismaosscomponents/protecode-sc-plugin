package com.synopsys.protecode.sc.jenkins;

import hudson.FilePath;

import java.io.File;

/**
 * Provide build information. Abstracts either AbstractBuild (standard build step)
 * or Run (pipeline)
 */
public interface BuildInformation {
    File getArtifactsDir();
    FilePath getWorkspace();
    int getNumber();
    String getAbsoluteUrl();
}

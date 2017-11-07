package com.synopsys.protecode.sc.jenkins;

import java.io.IOException;
import java.util.List;

/**
 * Provide a list of artifacts to scan
 */
public interface ArtifactsProvider {
    List<Artifact> getArtifacts() throws IOException, InterruptedException;
}

package com.synopsys.protecode.sc.jenkins;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.HostnameRequirement;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.google.common.collect.ImmutableMap;
import com.synopsys.protecode.sc.jenkins.exceptions.ApiAuthenticationException;
import com.synopsys.protecode.sc.jenkins.exceptions.ApiException;
import hudson.FilePath;
import hudson.security.ACL;
import jenkins.model.Jenkins;
import org.apache.commons.lang.StringUtils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ProtecodeScanRunner {

    private static final String PROTECODE_FILE_TAG = "protecodesc";
    private ProtecodeScIntegrator.DescriptorImpl descriptor;
    private String credentialsId;
    private String protecodeScGroup;
    private String artifactDir;
    private int scanTimeout;
    private boolean convertToSummary;
    private boolean leaveArtifacts;
    private boolean failIfVulns;

    public ProtecodeScanRunner(ProtecodeScIntegrator.DescriptorImpl descriptor,
                               String credentialsId,
                               String protecodeScGroup,
                               String artifactDir,
                               int scanTimeout,
                               boolean convertToSummary,
                               boolean leaveArtifacts,
                               boolean failIfVulns) {
        this.descriptor = descriptor;
        this.credentialsId = credentialsId;
        this.protecodeScGroup = protecodeScGroup;
        this.artifactDir = artifactDir;
        this.scanTimeout = scanTimeout;
        this.convertToSummary = convertToSummary;
        this.leaveArtifacts = leaveArtifacts;
        this.failIfVulns = failIfVulns;
    }

    private static void convertToSummary(PrintStream log,
                                         BuildInformation build, FilePath jsonReportDirectory) throws IOException, InterruptedException {
        log.println("Creating xml for summary plugin");
        ObjectMapper mapper = getObjectMapper();
        try {
            FilePath[] jsonFiles = jsonReportDirectory.list("*-" + PROTECODE_FILE_TAG + ".json");
            log.println(jsonFiles.length + " files found");
            File xmlReportDir = build.getArtifactsDir();
            if (!xmlReportDir.exists()) {
                boolean xmlReportDirCreated = xmlReportDir.mkdirs();
                if (!xmlReportDirCreated) {
                    log.println("XML report directory could not be created.");
                    throw new IOException("XML report directory could not be created.");
                }
            }
            File xmlFile = new File(xmlReportDir, PROTECODE_FILE_TAG + ".xml");

            log.println("Creating xml report to " + xmlFile.getName());

            OutputStream out = new BufferedOutputStream(
                    new FileOutputStream(xmlFile));
            createXmlReport(jsonFiles, mapper, out);
            out.close();
        } catch (NullPointerException e) {
            // NOP
        }
    }

    static void createXmlReport(final FilePath[] jsonFiles, final ObjectMapper mapper,
                                OutputStream xmlFile) throws IOException, InterruptedException {

        PrintStream out = new PrintStream(xmlFile, false, "UTF-8");
        out.println(
                "<section name=\"Protecode SC analysis result\" fontcolor=\"#000000\">");
        for (FilePath jsonFile : jsonFiles) {
            try (InputStream in = new BufferedInputStream(jsonFile.read())) {
                ProtecodeSc psc = mapper.readValue(in, ProtecodeSc.class);
                Long exact = psc.getResults().getSummary().getVulnCount()
                        .getExact();
                String verdict = psc.getResults().getSummary().getVerdict()
                        .getShortDesc();
                String verdict_detailed = psc.getResults().getSummary().getVerdict()
                        .getDetailed();
                out.println("<accordion name =\"" + psc.getArtifactName()
                        + " (" + verdict + ")\">");

                Color color = exact > 0L ? Color.RED : Color.GREEN;
                writeField(out, "Verdict", verdict_detailed, color);
                writeField(out, "Vulnerabilities", exact.toString(), Color.BLACK);
                writeField(out, "Report", "", Color.BLACK,
                        "<a target=\"_blank\" href=\""
                                + psc.getResults().getReport_url()
                                + "\">View full report in Protecode SC </a>");
                out.println("</accordion>");
            }
        }
        out.println("</section>");
        out.close();
    }

    private static void writeField(PrintStream out, String name, String value,
                                   Color valueColor) {
        writeField(out, name, value, valueColor, null);
    }

    private static void writeField(PrintStream out, String name, String value,
                                   Color valueColor, String cdata) {
        out.append("<field name=\"" + name + "\" titlecolor=\"black\" value=\""
                + value + "\" ");
        out.append("detailcolor=\"" + valueColor.getValue() + "\">\n");
        if (cdata != null && !cdata.isEmpty()) {
            out.print("<![CDATA[");
            out.print(cdata);
            out.print("]]>");
        }
        out.append("</field>\n");
    }

    private static ObjectMapper getObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        mapper.configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true);
        mapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        return mapper;
    }

    private static void writeJson(PrintStream log, ObjectMapper mapper,
                                  FilePath workspaceJsonReportDirectory, HttpApiConnector.PollResult result) {
        if (result == null || result.getProtecodeSc() == null) {
            log.println("No scan result!!");
            return;
        }
        FilePath jsonFile = workspaceJsonReportDirectory.child(
                result.getArtifactName() + "-" + PROTECODE_FILE_TAG + ".json");

        try (OutputStream out = new BufferedOutputStream(jsonFile.write())) {
            mapper.writeValue(out, result.getProtecodeSc());
        } catch (IOException e) {
            log.println(e.toString());
        } catch (InterruptedException e) {
            log.println(e.toString());
        }
    }

    public boolean perform(BuildInformation build, ArtifactsProvider artifactsProvider, PrintStream log) throws IOException, InterruptedException {
        log.println("Getting Protecode SC host and credentials");
        String host = descriptor.getProtecodeScHost();

        StandardUsernamePasswordCredentials creds = CredentialsMatchers
                .firstOrNull(
                        CredentialsProvider.lookupCredentials(
                                StandardUsernamePasswordCredentials.class,
                                Jenkins.getInstance(), ACL.SYSTEM,
                                new HostnameRequirement(host)),
                        CredentialsMatchers.withId(credentialsId));
        if (creds == null) {
            log.println("No Protecode SC credentials found");
            return false;
        }
        String protecodeScUser = creds.getUsername();
        String protecodeScPass = creds.getPassword().getPlainText();

        log.println("Connecting to Protecode SC host at " + host + " as "
                + protecodeScUser);
        boolean dontCheckCert = descriptor.isDontCheckCert();
        final List<Artifact> artifacts = artifactsProvider.getArtifacts();
        List<ApiPoller> identifiers = new ArrayList<>();
        for (Artifact artifact : artifacts) {
            log.println("Scanning artifact " + artifact.getName());
            HttpApiConnector connector = new HttpApiConnector(
                    log, artifact, host, protecodeScGroup,
                    protecodeScUser, protecodeScPass, dontCheckCert);
            Map<String, String> scanMetadata = ImmutableMap.of("build-id",
                    "" + build.getNumber(), "build-url",
                    build.getAbsoluteUrl());
            try {
                connector.init();
                String protecodeScIdentifier = connector.sendFile(artifact, scanMetadata);
                identifiers
                        .add(new ApiPoller(connector, protecodeScIdentifier));
            } catch (KeyManagementException | NoSuchAlgorithmException e) {
                throw new IOException(e);
            } catch (ApiAuthenticationException e) {
                log.println(e.getMessage());
                log.println("Failed to scan artifact");
                return false;
            } catch (ApiException e) {
                log.println(e.getMessage());
                return false;
            }
        }
        if (identifiers.isEmpty()) {
            log.println("No artifacts to scan!!");
            return false;
        }

        long stop = System.currentTimeMillis() + 1000L * 60 * scanTimeout;
        boolean poll = true;
        log.println("Waiting for scans to complete");
        while (poll) {
            boolean resultsLeft = false;
            for (ApiPoller poller : identifiers) {
                if (!poller.isScanned()) {

                    HttpApiConnector.PollResult p = null;

                    p = poller.poll();

                    if (p != null && !p.isReady()) {
                        resultsLeft = true;
                    }
                }
            }
            if (System.currentTimeMillis() > stop || !resultsLeft) {
                poll = false;
            }
            if (poll) {
                log.println("Waiting 10 more seconds...");
                Thread.sleep(10 * 1000);
            }
        }

        FilePath jsonReportDirectory = build.getWorkspace().child("reports");
        jsonReportDirectory.mkdirs();
        if (!jsonReportDirectory.isDirectory()) {
            log.println("Report directory could not be created.");
            return false;
        }

        ObjectMapper mapper = getObjectMapper();
        for (ApiPoller poller : identifiers) {
            writeJson(log, mapper, jsonReportDirectory, poller.getResult());
        }
        boolean vulns = false;
        for (ApiPoller poller : identifiers) {
            HttpApiConnector.PollResult r = poller.getResult();
            poller.getConnector().close();
            if (r == null || !r.isOk()) {
                if (r == null) {
                    log.println("No Protecode SC result available");
                }
                vulns = true;
            }
        }
        if (convertToSummary) {
            convertToSummary(log, build, jsonReportDirectory);
        }
        if (!leaveArtifacts && !StringUtils.isEmpty(artifactDir)) {
            build.getWorkspace().child(artifactDir).deleteContents();
        }
        return !(vulns && failIfVulns);

    }

    private static enum Color {
        RED("#ff0000"), GREEN("#00ff00"), YELLOW("#ff9c00"), BLACK("#000000");

        private String value;

        private Color(String value) {
            this.value = value;
        }

        String getValue() {
            return value;
        }
    }

    private static class ApiPoller {
        private String id;
        private boolean scanned;
        private HttpApiConnector connector;
        private HttpApiConnector.PollResult result;

        ApiPoller(HttpApiConnector connector, String id) {
            this.connector = connector;

            this.id = id;
        }

        boolean isScanned() {
            return scanned;
        }

        HttpApiConnector.PollResult poll() {

            result = connector.poll(id);
            if (result.isReady()) {
                scanned = true;
            }
            return result;
        }

        public HttpApiConnector.PollResult getResult() {
            return result;
        }

        HttpApiConnector getConnector() {
            return connector;
        }

    }

}

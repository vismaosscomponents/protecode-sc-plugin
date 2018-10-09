package com.synopsys.protecode.sc.jenkins;

import com.synopsys.protecode.sc.jenkins.exceptions.ApiException;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import static org.junit.Assert.*;
import static org.junit.Assume.assumeNotNull;

public class HttpApiConnectorTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(HttpApiConnector.class);

    private static final String PROTECODE_SC_USER = System.getenv("PROTECODE_SC_USER");
    private static final String PROTECODE_SC_PASS = System.getenv("PROTECODE_SC_PASS");
    private static final String PROTECODE_SC_GROUP = System.getenv("PROTECODE_SC_GROUP");

    @BeforeClass
    public static void setup() {
        // skip tests if env variables are not set
        assumeNotNull(PROTECODE_SC_USER, PROTECODE_SC_PASS, PROTECODE_SC_GROUP);
    }

    @Test
    public void testDownload1() throws NoSuchAlgorithmException, ApiException, InterruptedException, IOException, KeyManagementException {
        HttpApiConnector.PollResult poll = getPollResult("requirements.txt");
        assertTrue(poll.isOk());
        assertEquals(0, poll.getProtecodeSc().getResults().getComponents().size());
    }

    @Test
    public void testDownload2() throws NoSuchAlgorithmException, ApiException, InterruptedException, IOException, KeyManagementException {

        HttpApiConnector.PollResult poll = getPollResult("jackson-databind-2.1.2.zip");
        assertFalse(poll.isOk());
        assertEquals(5, poll.getProtecodeSc().getResults().getSummary().getVulnCount().getExact().longValue());
        assertEquals(1, poll.getProtecodeSc().getResults().getComponents().size());
        assertEquals(5, poll.getProtecodeSc().getResults().getComponents().get(0).getVulnCount().getExact().longValue());
    }

    @Test
    public void testDownload3() throws NoSuchAlgorithmException, ApiException, InterruptedException, IOException, KeyManagementException {
        HttpApiConnector.PollResult poll = getPollResult("jackson-databind-2.9.7.zip");
        assertTrue(poll.isOk());
        assertEquals(0, poll.getProtecodeSc().getResults().getSummary().getVulnCount().getExact().longValue());
        assertEquals(1, poll.getProtecodeSc().getResults().getComponents().size());
        assertEquals(0, poll.getProtecodeSc().getResults().getComponents().get(0).getVulnCount().getExact().longValue());
    }

    private static HttpApiConnector.PollResult getPollResult(String name) throws KeyManagementException, NoSuchAlgorithmException, IOException, ApiException, InterruptedException {
        PrintStream printStream = new PrintStream(System.out);
        Artifact artifact = new Artifact(new File(Thread.currentThread().getContextClassLoader().getResource(name).getFile()));
        HttpApiConnector httpApiConnector = new HttpApiConnector(printStream, artifact, "https://protecode-sc.com/", PROTECODE_SC_GROUP, PROTECODE_SC_USER, PROTECODE_SC_PASS, false);
        httpApiConnector.init();
        String protecodeScIdentifier = httpApiConnector.sendFile(artifact, new HashMap<String, String>());
        LOGGER.info(protecodeScIdentifier);

        boolean ready = false;
        HttpApiConnector.PollResult poll = null;
        while (!ready) {
            poll = httpApiConnector.poll(protecodeScIdentifier);
            ready = poll.isReady();
        }
        return poll;
    }

}

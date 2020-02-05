package io.snyk.plugins.nexus.scanner;

import javax.inject.Named;
import javax.inject.Singleton;
import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.snyk.sdk.Snyk;
import io.snyk.sdk.api.v1.SnykClient;
import io.snyk.sdk.model.TestResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonatype.nexus.repository.maven.MavenPath;
import retrofit2.Response;

@Named
@Singleton
public class MavenScanner {
  private static final Logger LOG = LoggerFactory.getLogger(MavenScanner.class);

  private SnykClient snykClient;
  private final String apiToken = "ae5f2c3a-51e4-4cec-bb6a-ec7f7acafb9d";
  private final String organizationId = "20677ec3-85f3-4f00-9bea-881ff16c286e";

  public MavenScanner() throws Exception {
    snykClient = Snyk.newBuilder(new Snyk.Config(apiToken)).buildSync();
  }

  TestResult scan(MavenPath.Coordinates mavenCoordinates) {
    TestResult testResult = null;
    try {
      Response<TestResult> response = snykClient.testMaven(mavenCoordinates.getGroupId(),
                                                           mavenCoordinates.getArtifactId(),
                                                           mavenCoordinates.getVersion(),
                                                           organizationId,
                                                           null).execute();
      if (response.isSuccessful() && response.body() != null) {
        testResult = response.body();
        String responseAsText = new ObjectMapper().writeValueAsString(response.body());
        LOG.warn("testMaven response: {}", responseAsText);
      }
    } catch (IOException ex) {
      LOG.error("Could not test maven artifact: {}", mavenCoordinates, ex);

    }

    return testResult;
  }
}

import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenMantisSafe {

    private void logGoldenMantis(String data) {
        Logger goldenMantisLogger = Logger.getLogger("goldenMantis.audit");
        goldenMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleGoldenMantis() {
        String data;
        data = System.getenv("GOLDEN_MANTIS_USER");
        logGoldenMantis(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

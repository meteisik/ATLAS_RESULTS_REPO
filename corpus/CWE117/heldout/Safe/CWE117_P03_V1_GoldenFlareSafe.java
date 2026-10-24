import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenFlareSafe {

    private void logGoldenFlare(String data) {
        Logger goldenFlareLogger = Logger.getLogger("goldenFlare.audit");
        goldenFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleGoldenFlare() {
        String data;
        data = System.getenv("GOLDEN_FLARE_USER");
        logGoldenFlare(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

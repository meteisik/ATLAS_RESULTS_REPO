import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenFlare {

    private void logGoldenFlare(String data) {
        Logger goldenFlareLogger = Logger.getLogger("goldenFlare.audit");
        goldenFlareLogger.info("Login attempt for user " + data);
    }

    public void handleGoldenFlare() {
        String data;
        data = System.getenv("GOLDEN_FLARE_USER");
        logGoldenFlare(data);
    }
}

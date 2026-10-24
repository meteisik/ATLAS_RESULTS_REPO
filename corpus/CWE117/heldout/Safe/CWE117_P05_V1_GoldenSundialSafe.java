import java.util.logging.Logger;

public class CWE117_P05_V1_GoldenSundialSafe {

    private String goldenSundialData;

    private void logGoldenSundial() {
        String data = goldenSundialData;
        Logger goldenSundialLogger = Logger.getLogger("goldenSundial.audit");
        goldenSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleGoldenSundial() {
        String data;
        data = System.getenv("GOLDEN_SUNDIAL_USER");
        goldenSundialData = data;
        logGoldenSundial();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

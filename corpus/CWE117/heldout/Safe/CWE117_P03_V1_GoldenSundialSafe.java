import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenSundialSafe {

    private void logGoldenSundial(String data) {
        Logger goldenSundialLogger = Logger.getLogger("goldenSundial.audit");
        goldenSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleGoldenSundial() {
        String data;
        data = System.getenv("GOLDEN_SUNDIAL_USER");
        logGoldenSundial(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

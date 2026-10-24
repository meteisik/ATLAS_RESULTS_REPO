import java.util.logging.Logger;

public class CWE117_P01_V2_GoldenSundialSafe {

    public void handleGoldenSundial() {
        String data;
        if (true) {
            data = System.getenv("GOLDEN_SUNDIAL_USER");
        } else {
            data = null;
        }
        Logger goldenSundialLogger = Logger.getLogger("goldenSundial.audit");
        goldenSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

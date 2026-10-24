import java.util.logging.Logger;

public class CWE117_P02_V2_GoldenSundialSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleGoldenSundial() {
        String dataCopy;
        {
            String data;
            if (PRIVATE_STATIC_FINAL_TRUE) {
                data = System.getenv("GOLDEN_SUNDIAL_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenSundialLogger = Logger.getLogger("goldenSundial.audit");
            goldenSundialLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

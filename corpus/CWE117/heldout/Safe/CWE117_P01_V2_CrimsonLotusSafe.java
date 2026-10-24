import java.util.logging.Logger;

public class CWE117_P01_V2_CrimsonLotusSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleCrimsonLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("CRIMSON_LOTUS_USER");
        } else {
            data = null;
        }
        Logger crimsonLotusLogger = Logger.getLogger("crimsonLotus.audit");
        crimsonLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

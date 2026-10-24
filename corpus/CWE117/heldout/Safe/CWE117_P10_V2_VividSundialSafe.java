import java.util.logging.Logger;

public class CWE117_P10_V2_VividSundialSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public void handleVividSundial() {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("VIVID_SUNDIAL_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_VividSundialSafeSink()).logVividSundial();
    }
}

class CWE117_P10_V2_VividSundialSafeSink {
    public void logVividSundial() {
        String data = CWE117_P10_V2_VividSundialSafe.data;
        Logger vividSundialLogger = Logger.getLogger("vividSundial.audit");
        vividSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

import java.util.logging.Logger;

public class CWE117_P10_V2_AmberSundialSafe {
    private static boolean privateReturnsTrue() { return true; }

    public static String data;

    public void handleAmberSundial() {
        if (privateReturnsTrue()) {
            data = System.getenv("AMBER_SUNDIAL_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberSundialSafeSink()).logAmberSundial();
    }
}

class CWE117_P10_V2_AmberSundialSafeSink {
    public void logAmberSundial() {
        String data = CWE117_P10_V2_AmberSundialSafe.data;
        Logger amberSundialLogger = Logger.getLogger("amberSundial.audit");
        amberSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

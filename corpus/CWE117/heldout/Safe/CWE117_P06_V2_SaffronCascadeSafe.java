import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronCascadeSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleSaffronCascade() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SAFFRON_CASCADE_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SaffronCascadeSafeSink()).logSaffronCascade(data);
    }
}

class CWE117_P06_V2_SaffronCascadeSafeSink {
    public void logSaffronCascade(String data) {
        Logger saffronCascadeLogger = Logger.getLogger("saffronCascade.audit");
        saffronCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

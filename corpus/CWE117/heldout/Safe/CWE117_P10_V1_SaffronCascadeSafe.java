import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronCascadeSafe {

    public static String data;

    public void handleSaffronCascade() {
        data = System.getenv("SAFFRON_CASCADE_USER");
        (new CWE117_P10_V1_SaffronCascadeSafeSink()).logSaffronCascade();
    }
}

class CWE117_P10_V1_SaffronCascadeSafeSink {
    public void logSaffronCascade() {
        String data = CWE117_P10_V1_SaffronCascadeSafe.data;
        Logger saffronCascadeLogger = Logger.getLogger("saffronCascade.audit");
        saffronCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

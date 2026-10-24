import java.util.logging.Logger;

public class CWE117_P10_V2_AmberCascadeSafe {

    public static String data;

    public void handleAmberCascade() {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AMBER_CASCADE_USER");
        }
        (new CWE117_P10_V2_AmberCascadeSafeSink()).logAmberCascade();
    }
}

class CWE117_P10_V2_AmberCascadeSafeSink {
    public void logAmberCascade() {
        String data = CWE117_P10_V2_AmberCascadeSafe.data;
        Logger amberCascadeLogger = Logger.getLogger("amberCascade.audit");
        amberCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

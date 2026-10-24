import java.util.logging.Logger;

public class CWE117_P01_V1_AmberCascadeSafe {

    public void handleAmberCascade() {
        String data;
        data = System.getenv("AMBER_CASCADE_USER");
        Logger amberCascadeLogger = Logger.getLogger("amberCascade.audit");
        amberCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

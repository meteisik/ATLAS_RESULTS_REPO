import java.util.logging.Logger;

public class CWE117_P01_V1_AmberPrismSafe {

    public void handleAmberPrism() {
        String data;
        data = System.getenv("AMBER_PRISM_USER");
        Logger amberPrismLogger = Logger.getLogger("amberPrism.audit");
        amberPrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

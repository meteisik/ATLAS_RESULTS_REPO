import java.util.logging.Logger;

public class CWE117_P05_V1_JadePrismSafe {

    private String jadePrismData;

    private void logJadePrism() {
        String data = jadePrismData;
        Logger jadePrismLogger = Logger.getLogger("jadePrism.audit");
        jadePrismLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadePrism() {
        String data;
        data = System.getenv("JADE_PRISM_USER");
        jadePrismData = data;
        logJadePrism();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

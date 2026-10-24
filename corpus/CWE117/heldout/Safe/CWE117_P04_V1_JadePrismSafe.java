import java.util.logging.Logger;

public class CWE117_P04_V1_JadePrismSafe {

    private String readJadePrism() {
        String data;
        data = System.getenv("JADE_PRISM_USER");
        return data;
    }

    public void handleJadePrism() {
        String data = readJadePrism();
        Logger jadePrismLogger = Logger.getLogger("jadePrism.audit");
        jadePrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

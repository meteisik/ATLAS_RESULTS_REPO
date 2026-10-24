import java.util.logging.Logger;

public class CWE117_P06_V1_JadePrismSafe {

    public void handleJadePrism() {
        String data;
        data = System.getenv("JADE_PRISM_USER");
        (new CWE117_P06_V1_JadePrismSafeSink()).logJadePrism(data);
    }
}

class CWE117_P06_V1_JadePrismSafeSink {
    public void logJadePrism(String data) {
        Logger jadePrismLogger = Logger.getLogger("jadePrism.audit");
        jadePrismLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

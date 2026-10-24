import java.util.logging.Logger;

public class CWE117_P03_V2_JadeAuroraSafe {

    private void logJadeAurora(String data) {
        Logger jadeAuroraLogger = Logger.getLogger("jadeAurora.audit");
        jadeAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadeAurora() {
        String data;
        if (true) {
            data = System.getenv("JADE_AURORA_USER");
        } else {
            data = null;
        }
        logJadeAurora(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

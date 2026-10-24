import java.util.logging.Logger;

public class CWE117_P05_V1_JadeAuroraSafe {

    private String jadeAuroraData;

    private void logJadeAurora() {
        String data = jadeAuroraData;
        Logger jadeAuroraLogger = Logger.getLogger("jadeAurora.audit");
        jadeAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadeAurora() {
        String data;
        data = System.getenv("JADE_AURORA_USER");
        jadeAuroraData = data;
        logJadeAurora();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

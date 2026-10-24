import java.util.logging.Logger;

public class CWE117_P04_V1_JadeAuroraSafe {

    private String readJadeAurora() {
        String data;
        data = System.getenv("JADE_AURORA_USER");
        return data;
    }

    public void handleJadeAurora() {
        String data = readJadeAurora();
        Logger jadeAuroraLogger = Logger.getLogger("jadeAurora.audit");
        jadeAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

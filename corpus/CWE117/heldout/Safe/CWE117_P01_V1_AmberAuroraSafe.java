import java.util.logging.Logger;

public class CWE117_P01_V1_AmberAuroraSafe {

    public void handleAmberAurora() {
        String data;
        data = System.getenv("AMBER_AURORA_USER");
        Logger amberAuroraLogger = Logger.getLogger("amberAurora.audit");
        amberAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

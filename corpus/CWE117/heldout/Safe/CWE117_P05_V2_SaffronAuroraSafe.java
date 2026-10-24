import java.util.logging.Logger;

public class CWE117_P05_V2_SaffronAuroraSafe {
    private static boolean privateTrue = true;

    private String saffronAuroraData;

    private void logSaffronAurora() {
        String data = saffronAuroraData;
        Logger saffronAuroraLogger = Logger.getLogger("saffronAurora.audit");
        saffronAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleSaffronAurora() {
        String data;
        if (privateTrue) {
            data = System.getenv("SAFFRON_AURORA_USER");
        } else {
            data = null;
        }
        saffronAuroraData = data;
        logSaffronAurora();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

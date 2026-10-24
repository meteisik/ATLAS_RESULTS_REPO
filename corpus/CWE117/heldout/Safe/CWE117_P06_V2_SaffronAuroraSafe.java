import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronAuroraSafe {
    private static int privateFive = 5;

    public void handleSaffronAurora() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("SAFFRON_AURORA_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SaffronAuroraSafeSink()).logSaffronAurora(data);
    }
}

class CWE117_P06_V2_SaffronAuroraSafeSink {
    public void logSaffronAurora(String data) {
        Logger saffronAuroraLogger = Logger.getLogger("saffronAurora.audit");
        saffronAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

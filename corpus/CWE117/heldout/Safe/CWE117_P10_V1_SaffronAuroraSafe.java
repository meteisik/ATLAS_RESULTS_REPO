import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronAuroraSafe {

    public static String data;

    public void handleSaffronAurora() {
        data = System.getenv("SAFFRON_AURORA_USER");
        (new CWE117_P10_V1_SaffronAuroraSafeSink()).logSaffronAurora();
    }
}

class CWE117_P10_V1_SaffronAuroraSafeSink {
    public void logSaffronAurora() {
        String data = CWE117_P10_V1_SaffronAuroraSafe.data;
        Logger saffronAuroraLogger = Logger.getLogger("saffronAurora.audit");
        saffronAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

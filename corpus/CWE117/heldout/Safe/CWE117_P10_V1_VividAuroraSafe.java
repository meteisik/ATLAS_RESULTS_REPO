import java.util.logging.Logger;

public class CWE117_P10_V1_VividAuroraSafe {

    public static String data;

    public void handleVividAurora() {
        data = System.getenv("VIVID_AURORA_USER");
        (new CWE117_P10_V1_VividAuroraSafeSink()).logVividAurora();
    }
}

class CWE117_P10_V1_VividAuroraSafeSink {
    public void logVividAurora() {
        String data = CWE117_P10_V1_VividAuroraSafe.data;
        Logger vividAuroraLogger = Logger.getLogger("vividAurora.audit");
        vividAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

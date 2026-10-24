import java.util.logging.Logger;

public class CWE117_P10_V2_AmberAuroraSafe {

    public static String data;

    public void handleAmberAurora() {
        while (true) {
            data = System.getenv("AMBER_AURORA_USER");
            break;
        }
        (new CWE117_P10_V2_AmberAuroraSafeSink()).logAmberAurora();
    }
}

class CWE117_P10_V2_AmberAuroraSafeSink {
    public void logAmberAurora() {
        String data = CWE117_P10_V2_AmberAuroraSafe.data;
        Logger amberAuroraLogger = Logger.getLogger("amberAurora.audit");
        amberAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

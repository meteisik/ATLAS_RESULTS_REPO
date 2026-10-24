import java.util.logging.Logger;

public class CWE117_P10_V1_VividAurora {

    public static String data;

    public void handleVividAurora() {
        data = System.getenv("VIVID_AURORA_USER");
        (new CWE117_P10_V1_VividAuroraSink()).logVividAurora();
    }
}

class CWE117_P10_V1_VividAuroraSink {
    public void logVividAurora() {
        String data = CWE117_P10_V1_VividAurora.data;
        Logger vividAuroraLogger = Logger.getLogger("vividAurora.audit");
        vividAuroraLogger.info("Login attempt for user " + data);
    }
}

import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronAurora {

    public static String data;

    public void handleSaffronAurora() {
        data = System.getenv("SAFFRON_AURORA_USER");
        (new CWE117_P10_V1_SaffronAuroraSink()).logSaffronAurora();
    }
}

class CWE117_P10_V1_SaffronAuroraSink {
    public void logSaffronAurora() {
        String data = CWE117_P10_V1_SaffronAurora.data;
        Logger saffronAuroraLogger = Logger.getLogger("saffronAurora.audit");
        saffronAuroraLogger.info("Login attempt for user " + data);
    }
}

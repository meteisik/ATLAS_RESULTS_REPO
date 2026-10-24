import java.util.logging.Logger;

public class CWE117_P10_V2_AmberAurora {

    public static String data;

    public void handleAmberAurora() {
        while (true) {
            data = System.getenv("AMBER_AURORA_USER");
            break;
        }
        (new CWE117_P10_V2_AmberAuroraSink()).logAmberAurora();
    }
}

class CWE117_P10_V2_AmberAuroraSink {
    public void logAmberAurora() {
        String data = CWE117_P10_V2_AmberAurora.data;
        Logger amberAuroraLogger = Logger.getLogger("amberAurora.audit");
        amberAuroraLogger.info("Login attempt for user " + data);
    }
}

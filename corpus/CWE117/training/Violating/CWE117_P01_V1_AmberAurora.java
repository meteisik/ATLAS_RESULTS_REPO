import java.util.logging.Logger;

public class CWE117_P01_V1_AmberAurora {

    public void handleAmberAurora() {
        String data;
        data = System.getenv("AMBER_AURORA_USER");
        Logger amberAuroraLogger = Logger.getLogger("amberAurora.audit");
        amberAuroraLogger.info("Login attempt for user " + data);
    }
}

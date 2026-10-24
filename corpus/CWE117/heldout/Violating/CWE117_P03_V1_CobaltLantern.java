import java.util.logging.Logger;

public class CWE117_P03_V1_CobaltLantern {

    private void logCobaltLantern(String data) {
        Logger cobaltLanternLogger = Logger.getLogger("cobaltLantern.audit");
        cobaltLanternLogger.info("Login attempt for user " + data);
    }

    public void handleCobaltLantern() {
        String data;
        data = System.getenv("COBALT_LANTERN_USER");
        logCobaltLantern(data);
    }
}

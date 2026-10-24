import java.util.logging.Logger;

public class CWE117_P01_V1_CobaltLantern {

    public void handleCobaltLantern() {
        String data;
        data = System.getenv("COBALT_LANTERN_USER");
        Logger cobaltLanternLogger = Logger.getLogger("cobaltLantern.audit");
        cobaltLanternLogger.info("Login attempt for user " + data);
    }
}

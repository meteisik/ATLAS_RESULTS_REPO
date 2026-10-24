import java.util.logging.Logger;

public class CWE117_P01_V1_CobaltRaven {

    public void handleCobaltRaven() {
        String data;
        data = System.getenv("COBALT_RAVEN_USER");
        Logger cobaltRavenLogger = Logger.getLogger("cobaltRaven.audit");
        cobaltRavenLogger.info("Login attempt for user " + data);
    }
}

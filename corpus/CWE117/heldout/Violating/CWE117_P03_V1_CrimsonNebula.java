import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonNebula {

    private void logCrimsonNebula(String data) {
        Logger crimsonNebulaLogger = Logger.getLogger("crimsonNebula.audit");
        crimsonNebulaLogger.info("Login attempt for user " + data);
    }

    public void handleCrimsonNebula() {
        String data;
        data = System.getenv("CRIMSON_NEBULA_USER");
        logCrimsonNebula(data);
    }
}

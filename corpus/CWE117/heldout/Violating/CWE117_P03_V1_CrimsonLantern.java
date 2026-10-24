import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonLantern {

    private void logCrimsonLantern(String data) {
        Logger crimsonLanternLogger = Logger.getLogger("crimsonLantern.audit");
        crimsonLanternLogger.info("Login attempt for user " + data);
    }

    public void handleCrimsonLantern() {
        String data;
        data = System.getenv("CRIMSON_LANTERN_USER");
        logCrimsonLantern(data);
    }
}

import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonComet {

    private void logCrimsonComet(String data) {
        Logger crimsonCometLogger = Logger.getLogger("crimsonComet.audit");
        crimsonCometLogger.info("Login attempt for user " + data);
    }

    public void handleCrimsonComet() {
        String data;
        data = System.getenv("CRIMSON_COMET_USER");
        logCrimsonComet(data);
    }
}

import java.util.logging.Logger;

public class CWE117_P03_V1_CrimsonCometSafe {

    private void logCrimsonComet(String data) {
        Logger crimsonCometLogger = Logger.getLogger("crimsonComet.audit");
        crimsonCometLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleCrimsonComet() {
        String data;
        data = System.getenv("CRIMSON_COMET_USER");
        logCrimsonComet(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

import java.util.logging.Logger;

public class CWE117_P01_V1_CrimsonCometSafe {

    public void handleCrimsonComet() {
        String data;
        data = System.getenv("CRIMSON_COMET_USER");
        Logger crimsonCometLogger = Logger.getLogger("crimsonComet.audit");
        crimsonCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

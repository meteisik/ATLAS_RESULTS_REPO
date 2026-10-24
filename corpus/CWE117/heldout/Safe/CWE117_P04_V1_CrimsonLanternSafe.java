import java.util.logging.Logger;

public class CWE117_P04_V1_CrimsonLanternSafe {

    private String readCrimsonLantern() {
        String data;
        data = System.getenv("CRIMSON_LANTERN_USER");
        return data;
    }

    public void handleCrimsonLantern() {
        String data = readCrimsonLantern();
        Logger crimsonLanternLogger = Logger.getLogger("crimsonLantern.audit");
        crimsonLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

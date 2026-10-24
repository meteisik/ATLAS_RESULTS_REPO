import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticLanternSafe {

    public void handleArcticLantern() {
        String data;
        data = System.getenv("ARCTIC_LANTERN_USER");
        Logger arcticLanternLogger = Logger.getLogger("arcticLantern.audit");
        arcticLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

import java.util.logging.Logger;

public class CWE117_P02_V1_ArcticLanternSafe {

    public void handleArcticLantern() {
        String dataCopy;
        {
            String data;
            data = System.getenv("ARCTIC_LANTERN_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger arcticLanternLogger = Logger.getLogger("arcticLantern.audit");
            arcticLanternLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

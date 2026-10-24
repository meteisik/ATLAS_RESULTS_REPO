import java.util.logging.Logger;

public class CWE117_P01_V2_JadeQuartzSafe {
    private static boolean privateTrue = true;

    public void handleJadeQuartz() {
        String data;
        if (privateTrue) {
            data = System.getenv("JADE_QUARTZ_USER");
        } else {
            data = null;
        }
        Logger jadeQuartzLogger = Logger.getLogger("jadeQuartz.audit");
        jadeQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

import java.util.logging.Logger;

public class CWE117_P05_V1_JadeQuartzSafe {

    private String jadeQuartzData;

    private void logJadeQuartz() {
        String data = jadeQuartzData;
        Logger jadeQuartzLogger = Logger.getLogger("jadeQuartz.audit");
        jadeQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleJadeQuartz() {
        String data;
        data = System.getenv("JADE_QUARTZ_USER");
        jadeQuartzData = data;
        logJadeQuartz();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

import java.util.logging.Logger;

public class CWE117_P04_V1_JadeQuartzSafe {

    private String readJadeQuartz() {
        String data;
        data = System.getenv("JADE_QUARTZ_USER");
        return data;
    }

    public void handleJadeQuartz() {
        String data = readJadeQuartz();
        Logger jadeQuartzLogger = Logger.getLogger("jadeQuartz.audit");
        jadeQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

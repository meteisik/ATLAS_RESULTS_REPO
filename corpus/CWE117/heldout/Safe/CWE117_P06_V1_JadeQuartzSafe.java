import java.util.logging.Logger;

public class CWE117_P06_V1_JadeQuartzSafe {

    public void handleJadeQuartz() {
        String data;
        data = System.getenv("JADE_QUARTZ_USER");
        (new CWE117_P06_V1_JadeQuartzSafeSink()).logJadeQuartz(data);
    }
}

class CWE117_P06_V1_JadeQuartzSafeSink {
    public void logJadeQuartz(String data) {
        Logger jadeQuartzLogger = Logger.getLogger("jadeQuartz.audit");
        jadeQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

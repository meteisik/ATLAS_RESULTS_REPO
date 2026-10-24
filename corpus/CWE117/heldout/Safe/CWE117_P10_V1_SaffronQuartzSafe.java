import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronQuartzSafe {

    public static String data;

    public void handleSaffronQuartz() {
        data = System.getenv("SAFFRON_QUARTZ_USER");
        (new CWE117_P10_V1_SaffronQuartzSafeSink()).logSaffronQuartz();
    }
}

class CWE117_P10_V1_SaffronQuartzSafeSink {
    public void logSaffronQuartz() {
        String data = CWE117_P10_V1_SaffronQuartzSafe.data;
        Logger saffronQuartzLogger = Logger.getLogger("saffronQuartz.audit");
        saffronQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

import java.util.logging.Logger;

public class CWE117_P10_V2_AmberQuartzSafe {
    private static int privateFive = 5;

    public static String data;

    public void handleAmberQuartz() {
        if (privateFive == 5) {
            data = System.getenv("AMBER_QUARTZ_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_AmberQuartzSafeSink()).logAmberQuartz();
    }
}

class CWE117_P10_V2_AmberQuartzSafeSink {
    public void logAmberQuartz() {
        String data = CWE117_P10_V2_AmberQuartzSafe.data;
        Logger amberQuartzLogger = Logger.getLogger("amberQuartz.audit");
        amberQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

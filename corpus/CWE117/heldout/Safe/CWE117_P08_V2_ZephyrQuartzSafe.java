import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrQuartzSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleZephyrQuartz() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("ZEPHYR_QUARTZ_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_ZephyrQuartzSafeSink()).logZephyrQuartz(dataArray);
    }
}

class CWE117_P08_V2_ZephyrQuartzSafeSink {
    public void logZephyrQuartz(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrQuartzLogger = Logger.getLogger("zephyrQuartz.audit");
        zephyrQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

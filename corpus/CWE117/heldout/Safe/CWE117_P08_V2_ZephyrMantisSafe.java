import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrMantisSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleZephyrMantis() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ZEPHYR_MANTIS_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_ZephyrMantisSafeSink()).logZephyrMantis(dataArray);
    }
}

class CWE117_P08_V2_ZephyrMantisSafeSink {
    public void logZephyrMantis(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrMantisLogger = Logger.getLogger("zephyrMantis.audit");
        zephyrMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

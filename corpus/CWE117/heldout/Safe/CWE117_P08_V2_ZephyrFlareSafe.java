import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrFlareSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void handleZephyrFlare() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ZEPHYR_FLARE_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_ZephyrFlareSafeSink()).logZephyrFlare(dataArray);
    }
}

class CWE117_P08_V2_ZephyrFlareSafeSink {
    public void logZephyrFlare(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrFlareLogger = Logger.getLogger("zephyrFlare.audit");
        zephyrFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

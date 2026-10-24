import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrFlare {
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
        (new CWE117_P08_V2_ZephyrFlareSink()).logZephyrFlare(dataArray);
    }
}

class CWE117_P08_V2_ZephyrFlareSink {
    public void logZephyrFlare(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrFlareLogger = Logger.getLogger("zephyrFlare.audit");
        zephyrFlareLogger.info("Login attempt for user " + data);
    }
}

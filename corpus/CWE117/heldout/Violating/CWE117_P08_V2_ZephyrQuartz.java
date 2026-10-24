import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrQuartz {
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
        (new CWE117_P08_V2_ZephyrQuartzSink()).logZephyrQuartz(dataArray);
    }
}

class CWE117_P08_V2_ZephyrQuartzSink {
    public void logZephyrQuartz(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrQuartzLogger = Logger.getLogger("zephyrQuartz.audit");
        zephyrQuartzLogger.info("Login attempt for user " + data);
    }
}

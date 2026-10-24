import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrAuroraSafe {

    public void handleZephyrAurora() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("ZEPHYR_AURORA_USER");
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_ZephyrAuroraSafeSink()).logZephyrAurora(dataArray);
    }
}

class CWE117_P08_V2_ZephyrAuroraSafeSink {
    public void logZephyrAurora(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrAuroraLogger = Logger.getLogger("zephyrAurora.audit");
        zephyrAuroraLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

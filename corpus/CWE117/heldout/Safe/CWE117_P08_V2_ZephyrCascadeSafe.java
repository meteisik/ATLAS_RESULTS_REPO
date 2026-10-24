import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrCascadeSafe {

    public void handleZephyrCascade() {
        String data;
        if (true) {
            data = System.getenv("ZEPHYR_CASCADE_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_ZephyrCascadeSafeSink()).logZephyrCascade(dataArray);
    }
}

class CWE117_P08_V2_ZephyrCascadeSafeSink {
    public void logZephyrCascade(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrCascadeLogger = Logger.getLogger("zephyrCascade.audit");
        zephyrCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

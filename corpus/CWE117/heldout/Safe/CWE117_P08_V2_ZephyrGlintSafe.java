import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrGlintSafe {
    private static boolean privateTrue = true;

    public void handleZephyrGlint() {
        String data;
        if (privateTrue) {
            data = System.getenv("ZEPHYR_GLINT_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_ZephyrGlintSafeSink()).logZephyrGlint(dataArray);
    }
}

class CWE117_P08_V2_ZephyrGlintSafeSink {
    public void logZephyrGlint(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrGlintLogger = Logger.getLogger("zephyrGlint.audit");
        zephyrGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

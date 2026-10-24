import java.util.logging.Logger;

public class CWE117_P08_V2_ZephyrGlint {
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
        (new CWE117_P08_V2_ZephyrGlintSink()).logZephyrGlint(dataArray);
    }
}

class CWE117_P08_V2_ZephyrGlintSink {
    public void logZephyrGlint(String[] dataArray) {
        String data = dataArray[2];
        Logger zephyrGlintLogger = Logger.getLogger("zephyrGlint.audit");
        zephyrGlintLogger.info("Login attempt for user " + data);
    }
}

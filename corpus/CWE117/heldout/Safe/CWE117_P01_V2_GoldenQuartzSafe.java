import java.util.logging.Logger;

public class CWE117_P01_V2_GoldenQuartzSafe {

    public void handleGoldenQuartz() {
        String data;
        while (true) {
            data = System.getenv("GOLDEN_QUARTZ_USER");
            break;
        }
        Logger goldenQuartzLogger = Logger.getLogger("goldenQuartz.audit");
        goldenQuartzLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

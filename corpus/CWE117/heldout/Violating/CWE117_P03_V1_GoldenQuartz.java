import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenQuartz {

    private void logGoldenQuartz(String data) {
        Logger goldenQuartzLogger = Logger.getLogger("goldenQuartz.audit");
        goldenQuartzLogger.info("Login attempt for user " + data);
    }

    public void handleGoldenQuartz() {
        String data;
        data = System.getenv("GOLDEN_QUARTZ_USER");
        logGoldenQuartz(data);
    }
}

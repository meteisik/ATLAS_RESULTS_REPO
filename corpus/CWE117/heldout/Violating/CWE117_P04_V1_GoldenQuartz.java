import java.util.logging.Logger;

public class CWE117_P04_V1_GoldenQuartz {

    private String readGoldenQuartz() {
        String data;
        data = System.getenv("GOLDEN_QUARTZ_USER");
        return data;
    }

    public void handleGoldenQuartz() {
        String data = readGoldenQuartz();
        Logger goldenQuartzLogger = Logger.getLogger("goldenQuartz.audit");
        goldenQuartzLogger.info("Login attempt for user " + data);
    }
}

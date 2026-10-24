import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenSignalSafe {

    private void logGoldenSignal(String data) {
        Logger goldenSignalLogger = Logger.getLogger("goldenSignal.audit");
        goldenSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleGoldenSignal() {
        String data;
        data = System.getenv("GOLDEN_SIGNAL_USER");
        logGoldenSignal(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

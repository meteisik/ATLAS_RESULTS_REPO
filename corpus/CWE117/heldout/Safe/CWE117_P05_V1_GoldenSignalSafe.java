import java.util.logging.Logger;

public class CWE117_P05_V1_GoldenSignalSafe {

    private String goldenSignalData;

    private void logGoldenSignal() {
        String data = goldenSignalData;
        Logger goldenSignalLogger = Logger.getLogger("goldenSignal.audit");
        goldenSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleGoldenSignal() {
        String data;
        data = System.getenv("GOLDEN_SIGNAL_USER");
        goldenSignalData = data;
        logGoldenSignal();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

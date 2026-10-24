import java.util.logging.Logger;

public class CWE117_P05_V1_GoldenSignal {

    private String goldenSignalData;

    private void logGoldenSignal() {
        String data = goldenSignalData;
        Logger goldenSignalLogger = Logger.getLogger("goldenSignal.audit");
        goldenSignalLogger.info("Login attempt for user " + data);
    }

    public void handleGoldenSignal() {
        String data;
        data = System.getenv("GOLDEN_SIGNAL_USER");
        goldenSignalData = data;
        logGoldenSignal();
    }
}

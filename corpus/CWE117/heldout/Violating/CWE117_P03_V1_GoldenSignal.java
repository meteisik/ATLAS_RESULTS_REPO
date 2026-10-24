import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenSignal {

    private void logGoldenSignal(String data) {
        Logger goldenSignalLogger = Logger.getLogger("goldenSignal.audit");
        goldenSignalLogger.info("Login attempt for user " + data);
    }

    public void handleGoldenSignal() {
        String data;
        data = System.getenv("GOLDEN_SIGNAL_USER");
        logGoldenSignal(data);
    }
}

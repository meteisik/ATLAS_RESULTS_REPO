import java.util.logging.Logger;

public class CWE117_P04_V1_GoldenSignal {

    private String readGoldenSignal() {
        String data;
        data = System.getenv("GOLDEN_SIGNAL_USER");
        return data;
    }

    public void handleGoldenSignal() {
        String data = readGoldenSignal();
        Logger goldenSignalLogger = Logger.getLogger("goldenSignal.audit");
        goldenSignalLogger.info("Login attempt for user " + data);
    }
}

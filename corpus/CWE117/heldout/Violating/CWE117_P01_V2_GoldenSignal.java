import java.util.logging.Logger;

public class CWE117_P01_V2_GoldenSignal {

    public void handleGoldenSignal() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("GOLDEN_SIGNAL_USER");
        }
        Logger goldenSignalLogger = Logger.getLogger("goldenSignal.audit");
        goldenSignalLogger.info("Login attempt for user " + data);
    }
}

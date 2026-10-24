import java.util.logging.Logger;

public class CWE117_P02_V2_GoldenSignal {

    public void handleGoldenSignal() {
        String dataCopy;
        {
            String data;
            if (5 == 5) {
                data = System.getenv("GOLDEN_SIGNAL_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenSignalLogger = Logger.getLogger("goldenSignal.audit");
            goldenSignalLogger.info("Login attempt for user " + data);
        }
    }
}

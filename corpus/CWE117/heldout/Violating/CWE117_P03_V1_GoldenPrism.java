import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenPrism {

    private void logGoldenPrism(String data) {
        Logger goldenPrismLogger = Logger.getLogger("goldenPrism.audit");
        goldenPrismLogger.info("Login attempt for user " + data);
    }

    public void handleGoldenPrism() {
        String data;
        data = System.getenv("GOLDEN_PRISM_USER");
        logGoldenPrism(data);
    }
}

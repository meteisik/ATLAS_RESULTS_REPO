import java.util.logging.Logger;

public class CWE117_P03_V1_GoldenAurora {

    private void logGoldenAurora(String data) {
        Logger goldenAuroraLogger = Logger.getLogger("goldenAurora.audit");
        goldenAuroraLogger.info("Login attempt for user " + data);
    }

    public void handleGoldenAurora() {
        String data;
        data = System.getenv("GOLDEN_AURORA_USER");
        logGoldenAurora(data);
    }
}

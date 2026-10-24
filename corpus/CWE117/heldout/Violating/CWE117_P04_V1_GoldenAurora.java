import java.util.logging.Logger;

public class CWE117_P04_V1_GoldenAurora {

    private String readGoldenAurora() {
        String data;
        data = System.getenv("GOLDEN_AURORA_USER");
        return data;
    }

    public void handleGoldenAurora() {
        String data = readGoldenAurora();
        Logger goldenAuroraLogger = Logger.getLogger("goldenAurora.audit");
        goldenAuroraLogger.info("Login attempt for user " + data);
    }
}

import java.util.logging.Logger;

public class CWE117_P02_V1_GoldenAuroraSafe {

    public void handleGoldenAurora() {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_AURORA_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenAuroraLogger = Logger.getLogger("goldenAurora.audit");
            goldenAuroraLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

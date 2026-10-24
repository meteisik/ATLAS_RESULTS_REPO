import java.util.logging.Logger;

public class CWE117_P04_V1_GoldenCascadeSafe {

    private String readGoldenCascade() {
        String data;
        data = System.getenv("GOLDEN_CASCADE_USER");
        return data;
    }

    public void handleGoldenCascade() {
        String data = readGoldenCascade();
        Logger goldenCascadeLogger = Logger.getLogger("goldenCascade.audit");
        goldenCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

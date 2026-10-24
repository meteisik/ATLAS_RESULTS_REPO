import java.util.logging.Logger;

public class CWE117_P04_V1_GoldenFlare {

    private String readGoldenFlare() {
        String data;
        data = System.getenv("GOLDEN_FLARE_USER");
        return data;
    }

    public void handleGoldenFlare() {
        String data = readGoldenFlare();
        Logger goldenFlareLogger = Logger.getLogger("goldenFlare.audit");
        goldenFlareLogger.info("Login attempt for user " + data);
    }
}

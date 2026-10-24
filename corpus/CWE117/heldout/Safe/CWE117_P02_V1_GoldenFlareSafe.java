import java.util.logging.Logger;

public class CWE117_P02_V1_GoldenFlareSafe {

    public void handleGoldenFlare() {
        String dataCopy;
        {
            String data;
            data = System.getenv("GOLDEN_FLARE_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger goldenFlareLogger = Logger.getLogger("goldenFlare.audit");
            goldenFlareLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

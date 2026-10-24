import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenFlareSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleGoldenFlare() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("GOLDEN_FLARE_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenFlareSafeBase baseObject = new CWE117_P12_V2_GoldenFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenFlareSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenFlareSafeSink extends CWE117_P12_V2_GoldenFlareSafeBase {
    public void action(String data) {
        Logger goldenFlareLogger = Logger.getLogger("goldenFlare.audit");
        goldenFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

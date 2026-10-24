import java.util.logging.Logger;

public class CWE117_P12_V2_GoldenFlare {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleGoldenFlare() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("GOLDEN_FLARE_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_GoldenFlareBase baseObject = new CWE117_P12_V2_GoldenFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_GoldenFlareBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_GoldenFlareSink extends CWE117_P12_V2_GoldenFlareBase {
    public void action(String data) {
        Logger goldenFlareLogger = Logger.getLogger("goldenFlare.audit");
        goldenFlareLogger.info("Login attempt for user " + data);
    }
}

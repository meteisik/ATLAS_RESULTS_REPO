import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrFlareSafe {

    public void handleZephyrFlare() {
        String data;
        data = System.getenv("ZEPHYR_FLARE_USER");
        CWE117_P12_V1_ZephyrFlareSafeBase baseObject = new CWE117_P12_V1_ZephyrFlareSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrFlareSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrFlareSafeSink extends CWE117_P12_V1_ZephyrFlareSafeBase {
    public void action(String data) {
        Logger zephyrFlareLogger = Logger.getLogger("zephyrFlare.audit");
        zephyrFlareLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrFlare {

    public void handleZephyrFlare() {
        String data;
        data = System.getenv("ZEPHYR_FLARE_USER");
        CWE117_P12_V1_ZephyrFlareBase baseObject = new CWE117_P12_V1_ZephyrFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrFlareBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrFlareSink extends CWE117_P12_V1_ZephyrFlareBase {
    public void action(String data) {
        Logger zephyrFlareLogger = Logger.getLogger("zephyrFlare.audit");
        zephyrFlareLogger.info("Login attempt for user " + data);
    }
}

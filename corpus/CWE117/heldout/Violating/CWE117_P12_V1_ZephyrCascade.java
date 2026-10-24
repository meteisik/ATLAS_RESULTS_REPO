import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrCascade {

    public void handleZephyrCascade() {
        String data;
        data = System.getenv("ZEPHYR_CASCADE_USER");
        CWE117_P12_V1_ZephyrCascadeBase baseObject = new CWE117_P12_V1_ZephyrCascadeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrCascadeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrCascadeSink extends CWE117_P12_V1_ZephyrCascadeBase {
    public void action(String data) {
        Logger zephyrCascadeLogger = Logger.getLogger("zephyrCascade.audit");
        zephyrCascadeLogger.info("Login attempt for user " + data);
    }
}

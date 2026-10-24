import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrAurora {

    public void handleZephyrAurora() {
        String data;
        data = System.getenv("ZEPHYR_AURORA_USER");
        CWE117_P12_V1_ZephyrAuroraBase baseObject = new CWE117_P12_V1_ZephyrAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrAuroraBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrAuroraSink extends CWE117_P12_V1_ZephyrAuroraBase {
    public void action(String data) {
        Logger zephyrAuroraLogger = Logger.getLogger("zephyrAurora.audit");
        zephyrAuroraLogger.info("Login attempt for user " + data);
    }
}

import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrMantis {

    public void handleZephyrMantis() {
        String data;
        data = System.getenv("ZEPHYR_MANTIS_USER");
        CWE117_P12_V1_ZephyrMantisBase baseObject = new CWE117_P12_V1_ZephyrMantisSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrMantisBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrMantisSink extends CWE117_P12_V1_ZephyrMantisBase {
    public void action(String data) {
        Logger zephyrMantisLogger = Logger.getLogger("zephyrMantis.audit");
        zephyrMantisLogger.info("Login attempt for user " + data);
    }
}

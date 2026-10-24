import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrSundial {

    public void handleZephyrSundial() {
        String data;
        data = System.getenv("ZEPHYR_SUNDIAL_USER");
        CWE117_P12_V1_ZephyrSundialBase baseObject = new CWE117_P12_V1_ZephyrSundialSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrSundialBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrSundialSink extends CWE117_P12_V1_ZephyrSundialBase {
    public void action(String data) {
        Logger zephyrSundialLogger = Logger.getLogger("zephyrSundial.audit");
        zephyrSundialLogger.info("Login attempt for user " + data);
    }
}

import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrPrism {

    public void handleZephyrPrism() {
        String data;
        data = System.getenv("ZEPHYR_PRISM_USER");
        CWE117_P12_V1_ZephyrPrismBase baseObject = new CWE117_P12_V1_ZephyrPrismSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrPrismBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrPrismSink extends CWE117_P12_V1_ZephyrPrismBase {
    public void action(String data) {
        Logger zephyrPrismLogger = Logger.getLogger("zephyrPrism.audit");
        zephyrPrismLogger.info("Login attempt for user " + data);
    }
}

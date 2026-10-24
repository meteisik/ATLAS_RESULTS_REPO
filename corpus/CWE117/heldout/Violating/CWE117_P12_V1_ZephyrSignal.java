import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrSignal {

    public void handleZephyrSignal() {
        String data;
        data = System.getenv("ZEPHYR_SIGNAL_USER");
        CWE117_P12_V1_ZephyrSignalBase baseObject = new CWE117_P12_V1_ZephyrSignalSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrSignalBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrSignalSink extends CWE117_P12_V1_ZephyrSignalBase {
    public void action(String data) {
        Logger zephyrSignalLogger = Logger.getLogger("zephyrSignal.audit");
        zephyrSignalLogger.info("Login attempt for user " + data);
    }
}

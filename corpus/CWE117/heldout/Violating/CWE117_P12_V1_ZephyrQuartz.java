import java.util.logging.Logger;

public class CWE117_P12_V1_ZephyrQuartz {

    public void handleZephyrQuartz() {
        String data;
        data = System.getenv("ZEPHYR_QUARTZ_USER");
        CWE117_P12_V1_ZephyrQuartzBase baseObject = new CWE117_P12_V1_ZephyrQuartzSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ZephyrQuartzBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ZephyrQuartzSink extends CWE117_P12_V1_ZephyrQuartzBase {
    public void action(String data) {
        Logger zephyrQuartzLogger = Logger.getLogger("zephyrQuartz.audit");
        zephyrQuartzLogger.info("Login attempt for user " + data);
    }
}

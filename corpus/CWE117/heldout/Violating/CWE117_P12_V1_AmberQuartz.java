import java.util.logging.Logger;

public class CWE117_P12_V1_AmberQuartz {

    public void handleAmberQuartz() {
        String data;
        data = System.getenv("AMBER_QUARTZ_USER");
        CWE117_P12_V1_AmberQuartzBase baseObject = new CWE117_P12_V1_AmberQuartzSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberQuartzBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberQuartzSink extends CWE117_P12_V1_AmberQuartzBase {
    public void action(String data) {
        Logger amberQuartzLogger = Logger.getLogger("amberQuartz.audit");
        amberQuartzLogger.info("Login attempt for user " + data);
    }
}

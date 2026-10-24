import java.util.logging.Logger;

public class CWE117_P12_V1_AmberPrism {

    public void handleAmberPrism() {
        String data;
        data = System.getenv("AMBER_PRISM_USER");
        CWE117_P12_V1_AmberPrismBase baseObject = new CWE117_P12_V1_AmberPrismSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_AmberPrismBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_AmberPrismSink extends CWE117_P12_V1_AmberPrismBase {
    public void action(String data) {
        Logger amberPrismLogger = Logger.getLogger("amberPrism.audit");
        amberPrismLogger.info("Login attempt for user " + data);
    }
}

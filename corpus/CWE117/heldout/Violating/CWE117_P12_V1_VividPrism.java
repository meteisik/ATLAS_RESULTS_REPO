import java.util.logging.Logger;

public class CWE117_P12_V1_VividPrism {

    public void handleVividPrism() {
        String data;
        data = System.getenv("VIVID_PRISM_USER");
        CWE117_P12_V1_VividPrismBase baseObject = new CWE117_P12_V1_VividPrismSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VividPrismBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VividPrismSink extends CWE117_P12_V1_VividPrismBase {
    public void action(String data) {
        Logger vividPrismLogger = Logger.getLogger("vividPrism.audit");
        vividPrismLogger.info("Login attempt for user " + data);
    }
}

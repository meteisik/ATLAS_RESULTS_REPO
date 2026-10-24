import java.util.logging.Logger;

public class CWE117_P12_V1_VividSignal {

    public void handleVividSignal() {
        String data;
        data = System.getenv("VIVID_SIGNAL_USER");
        CWE117_P12_V1_VividSignalBase baseObject = new CWE117_P12_V1_VividSignalSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VividSignalBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VividSignalSink extends CWE117_P12_V1_VividSignalBase {
    public void action(String data) {
        Logger vividSignalLogger = Logger.getLogger("vividSignal.audit");
        vividSignalLogger.info("Login attempt for user " + data);
    }
}

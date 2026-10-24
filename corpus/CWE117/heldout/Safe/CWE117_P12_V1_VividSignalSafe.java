import java.util.logging.Logger;

public class CWE117_P12_V1_VividSignalSafe {

    public void handleVividSignal() {
        String data;
        data = System.getenv("VIVID_SIGNAL_USER");
        CWE117_P12_V1_VividSignalSafeBase baseObject = new CWE117_P12_V1_VividSignalSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_VividSignalSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_VividSignalSafeSink extends CWE117_P12_V1_VividSignalSafeBase {
    public void action(String data) {
        Logger vividSignalLogger = Logger.getLogger("vividSignal.audit");
        vividSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

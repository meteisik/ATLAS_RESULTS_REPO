import java.util.logging.Logger;

public class CWE117_P10_V2_VividSignal {

    public static String data;

    public void handleVividSignal() {
        if (5 == 5) {
            data = System.getenv("VIVID_SIGNAL_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_VividSignalSink()).logVividSignal();
    }
}

class CWE117_P10_V2_VividSignalSink {
    public void logVividSignal() {
        String data = CWE117_P10_V2_VividSignal.data;
        Logger vividSignalLogger = Logger.getLogger("vividSignal.audit");
        vividSignalLogger.info("Login attempt for user " + data);
    }
}

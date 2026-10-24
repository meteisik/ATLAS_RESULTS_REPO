import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronSignal {

    public static String data;

    public void handleSaffronSignal() {
        data = System.getenv("SAFFRON_SIGNAL_USER");
        (new CWE117_P10_V1_SaffronSignalSink()).logSaffronSignal();
    }
}

class CWE117_P10_V1_SaffronSignalSink {
    public void logSaffronSignal() {
        String data = CWE117_P10_V1_SaffronSignal.data;
        Logger saffronSignalLogger = Logger.getLogger("saffronSignal.audit");
        saffronSignalLogger.info("Login attempt for user " + data);
    }
}

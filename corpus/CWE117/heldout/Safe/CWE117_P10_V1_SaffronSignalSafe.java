import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronSignalSafe {

    public static String data;

    public void handleSaffronSignal() {
        data = System.getenv("SAFFRON_SIGNAL_USER");
        (new CWE117_P10_V1_SaffronSignalSafeSink()).logSaffronSignal();
    }
}

class CWE117_P10_V1_SaffronSignalSafeSink {
    public void logSaffronSignal() {
        String data = CWE117_P10_V1_SaffronSignalSafe.data;
        Logger saffronSignalLogger = Logger.getLogger("saffronSignal.audit");
        saffronSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

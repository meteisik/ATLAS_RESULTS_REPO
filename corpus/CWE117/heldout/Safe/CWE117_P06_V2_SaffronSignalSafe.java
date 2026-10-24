import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronSignalSafe {

    public void handleSaffronSignal() {
        String data;
        while (true) {
            data = System.getenv("SAFFRON_SIGNAL_USER");
            break;
        }
        (new CWE117_P06_V2_SaffronSignalSafeSink()).logSaffronSignal(data);
    }
}

class CWE117_P06_V2_SaffronSignalSafeSink {
    public void logSaffronSignal(String data) {
        Logger saffronSignalLogger = Logger.getLogger("saffronSignal.audit");
        saffronSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

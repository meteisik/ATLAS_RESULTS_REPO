import java.util.logging.Logger;

public class CWE117_P07_V2_SaffronSignalSafe {

    public void handleSaffronSignal() {
        String data;
        if (true) {
            data = (new CWE117_P07_V2_SaffronSignalSafeSource()).readSaffronSignal();
        } else {
            data = null;
        }
        Logger saffronSignalLogger = Logger.getLogger("saffronSignal.audit");
        saffronSignalLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SaffronSignalSafeSource {
    public String readSaffronSignal() {
        String data;
        data = System.getenv("SAFFRON_SIGNAL_USER");
        return data;
    }
}

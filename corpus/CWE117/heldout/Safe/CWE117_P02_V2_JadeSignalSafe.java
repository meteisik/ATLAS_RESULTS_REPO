import java.util.logging.Logger;

public class CWE117_P02_V2_JadeSignalSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleJadeSignal() {
        String dataCopy;
        {
            String data;
            if (privateReturnsTrue()) {
                data = System.getenv("JADE_SIGNAL_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger jadeSignalLogger = Logger.getLogger("jadeSignal.audit");
            jadeSignalLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

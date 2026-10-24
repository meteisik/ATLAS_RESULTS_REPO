import java.util.logging.Logger;

public class CWE117_P06_V2_SaffronCascade {
    private static boolean privateReturnsTrue() { return true; }

    public void handleSaffronCascade() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SAFFRON_CASCADE_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SaffronCascadeSink()).logSaffronCascade(data);
    }
}

class CWE117_P06_V2_SaffronCascadeSink {
    public void logSaffronCascade(String data) {
        Logger saffronCascadeLogger = Logger.getLogger("saffronCascade.audit");
        saffronCascadeLogger.info("Login attempt for user " + data);
    }
}

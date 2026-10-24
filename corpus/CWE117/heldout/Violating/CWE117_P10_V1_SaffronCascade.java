import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronCascade {

    public static String data;

    public void handleSaffronCascade() {
        data = System.getenv("SAFFRON_CASCADE_USER");
        (new CWE117_P10_V1_SaffronCascadeSink()).logSaffronCascade();
    }
}

class CWE117_P10_V1_SaffronCascadeSink {
    public void logSaffronCascade() {
        String data = CWE117_P10_V1_SaffronCascade.data;
        Logger saffronCascadeLogger = Logger.getLogger("saffronCascade.audit");
        saffronCascadeLogger.info("Login attempt for user " + data);
    }
}

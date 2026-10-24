import java.util.logging.Logger;

public class CWE117_P10_V2_AmberCascade {

    public static String data;

    public void handleAmberCascade() {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AMBER_CASCADE_USER");
        }
        (new CWE117_P10_V2_AmberCascadeSink()).logAmberCascade();
    }
}

class CWE117_P10_V2_AmberCascadeSink {
    public void logAmberCascade() {
        String data = CWE117_P10_V2_AmberCascade.data;
        Logger amberCascadeLogger = Logger.getLogger("amberCascade.audit");
        amberCascadeLogger.info("Login attempt for user " + data);
    }
}

import java.util.logging.Logger;

public class CWE117_P01_V1_AmberCascade {

    public void handleAmberCascade() {
        String data;
        data = System.getenv("AMBER_CASCADE_USER");
        Logger amberCascadeLogger = Logger.getLogger("amberCascade.audit");
        amberCascadeLogger.info("Login attempt for user " + data);
    }
}

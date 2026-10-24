import java.util.logging.Logger;

public class CWE117_P01_V1_AmberPrism {

    public void handleAmberPrism() {
        String data;
        data = System.getenv("AMBER_PRISM_USER");
        Logger amberPrismLogger = Logger.getLogger("amberPrism.audit");
        amberPrismLogger.info("Login attempt for user " + data);
    }
}

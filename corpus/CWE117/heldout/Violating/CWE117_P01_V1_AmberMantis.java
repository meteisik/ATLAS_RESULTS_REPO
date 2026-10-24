import java.util.logging.Logger;

public class CWE117_P01_V1_AmberMantis {

    public void handleAmberMantis() {
        String data;
        data = System.getenv("AMBER_MANTIS_USER");
        Logger amberMantisLogger = Logger.getLogger("amberMantis.audit");
        amberMantisLogger.info("Login attempt for user " + data);
    }
}

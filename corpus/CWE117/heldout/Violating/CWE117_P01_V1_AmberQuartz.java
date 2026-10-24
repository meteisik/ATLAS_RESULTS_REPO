import java.util.logging.Logger;

public class CWE117_P01_V1_AmberQuartz {

    public void handleAmberQuartz() {
        String data;
        data = System.getenv("AMBER_QUARTZ_USER");
        Logger amberQuartzLogger = Logger.getLogger("amberQuartz.audit");
        amberQuartzLogger.info("Login attempt for user " + data);
    }
}

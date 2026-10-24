import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetMantis {

    public static String data;

    public void handleVelvetMantis() {
        data = System.getenv("VELVET_MANTIS_USER");
        (new CWE117_P10_V1_VelvetMantisSink()).logVelvetMantis();
    }
}

class CWE117_P10_V1_VelvetMantisSink {
    public void logVelvetMantis() {
        String data = CWE117_P10_V1_VelvetMantis.data;
        Logger velvetMantisLogger = Logger.getLogger("velvetMantis.audit");
        velvetMantisLogger.info("Login attempt for user " + data);
    }
}

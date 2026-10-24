import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetCascade {

    public static String data;

    public void handleVelvetCascade() {
        data = System.getenv("VELVET_CASCADE_USER");
        (new CWE117_P10_V1_VelvetCascadeSink()).logVelvetCascade();
    }
}

class CWE117_P10_V1_VelvetCascadeSink {
    public void logVelvetCascade() {
        String data = CWE117_P10_V1_VelvetCascade.data;
        Logger velvetCascadeLogger = Logger.getLogger("velvetCascade.audit");
        velvetCascadeLogger.info("Login attempt for user " + data);
    }
}

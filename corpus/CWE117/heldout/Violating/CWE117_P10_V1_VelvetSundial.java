import java.util.logging.Logger;

public class CWE117_P10_V1_VelvetSundial {

    public static String data;

    public void handleVelvetSundial() {
        data = System.getenv("VELVET_SUNDIAL_USER");
        (new CWE117_P10_V1_VelvetSundialSink()).logVelvetSundial();
    }
}

class CWE117_P10_V1_VelvetSundialSink {
    public void logVelvetSundial() {
        String data = CWE117_P10_V1_VelvetSundial.data;
        Logger velvetSundialLogger = Logger.getLogger("velvetSundial.audit");
        velvetSundialLogger.info("Login attempt for user " + data);
    }
}

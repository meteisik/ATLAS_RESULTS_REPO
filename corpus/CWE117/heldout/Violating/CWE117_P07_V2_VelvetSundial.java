import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetSundial {
    private static boolean privateReturnsTrue() { return true; }

    public void handleVelvetSundial() {
        String data;
        if (privateReturnsTrue()) {
            data = (new CWE117_P07_V2_VelvetSundialSource()).readVelvetSundial();
        } else {
            data = null;
        }
        Logger velvetSundialLogger = Logger.getLogger("velvetSundial.audit");
        velvetSundialLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_VelvetSundialSource {
    public String readVelvetSundial() {
        String data;
        data = System.getenv("VELVET_SUNDIAL_USER");
        return data;
    }
}

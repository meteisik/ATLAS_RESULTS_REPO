import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetCascadeSafe {

    public void handleVelvetCascade() {
        String data;
        while (true) {
            data = (new CWE117_P07_V2_VelvetCascadeSafeSource()).readVelvetCascade();
            break;
        }
        Logger velvetCascadeLogger = Logger.getLogger("velvetCascade.audit");
        velvetCascadeLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_VelvetCascadeSafeSource {
    public String readVelvetCascade() {
        String data;
        data = System.getenv("VELVET_CASCADE_USER");
        return data;
    }
}

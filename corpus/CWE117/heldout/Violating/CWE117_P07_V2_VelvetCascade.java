import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetCascade {

    public void handleVelvetCascade() {
        String data;
        while (true) {
            data = (new CWE117_P07_V2_VelvetCascadeSource()).readVelvetCascade();
            break;
        }
        Logger velvetCascadeLogger = Logger.getLogger("velvetCascade.audit");
        velvetCascadeLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_VelvetCascadeSource {
    public String readVelvetCascade() {
        String data;
        data = System.getenv("VELVET_CASCADE_USER");
        return data;
    }
}

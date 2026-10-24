import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetFlare {

    public void handleVelvetFlare() {
        String data;
        if (true) {
            data = (new CWE117_P07_V2_VelvetFlareSource()).readVelvetFlare();
        } else {
            data = null;
        }
        Logger velvetFlareLogger = Logger.getLogger("velvetFlare.audit");
        velvetFlareLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_VelvetFlareSource {
    public String readVelvetFlare() {
        String data;
        data = System.getenv("VELVET_FLARE_USER");
        return data;
    }
}

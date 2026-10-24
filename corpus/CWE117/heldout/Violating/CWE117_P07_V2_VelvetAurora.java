import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetAurora {

    public void handleVelvetAurora() {
        String data;
        switch (7) {
        case 7:
            data = (new CWE117_P07_V2_VelvetAuroraSource()).readVelvetAurora();
            break;
        default:
            data = null;
            break;
        }
        Logger velvetAuroraLogger = Logger.getLogger("velvetAurora.audit");
        velvetAuroraLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_VelvetAuroraSource {
    public String readVelvetAurora() {
        String data;
        data = System.getenv("VELVET_AURORA_USER");
        return data;
    }
}

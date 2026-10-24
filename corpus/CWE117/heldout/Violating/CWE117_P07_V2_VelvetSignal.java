import java.util.logging.Logger;

public class CWE117_P07_V2_VelvetSignal {
    private static int privateFive = 5;

    public void handleVelvetSignal() {
        String data;
        if (privateFive == 5) {
            data = (new CWE117_P07_V2_VelvetSignalSource()).readVelvetSignal();
        } else {
            data = null;
        }
        Logger velvetSignalLogger = Logger.getLogger("velvetSignal.audit");
        velvetSignalLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_VelvetSignalSource {
    public String readVelvetSignal() {
        String data;
        data = System.getenv("VELVET_SIGNAL_USER");
        return data;
    }
}

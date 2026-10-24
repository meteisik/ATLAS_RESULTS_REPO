import java.util.logging.Logger;

public class CWE117_P08_V2_VelvetCascade {

    public void handleVelvetCascade() {
        String data;
        if (true) {
            data = System.getenv("VELVET_CASCADE_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_VelvetCascadeSink()).logVelvetCascade(dataArray);
    }
}

class CWE117_P08_V2_VelvetCascadeSink {
    public void logVelvetCascade(String[] dataArray) {
        String data = dataArray[2];
        Logger velvetCascadeLogger = Logger.getLogger("velvetCascade.audit");
        velvetCascadeLogger.info("Login attempt for user " + data);
    }
}

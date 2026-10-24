import java.util.logging.Logger;

public class CWE117_P08_V2_SolarQuartz {

    public void handleSolarQuartz() {
        String data;
        while (true) {
            data = System.getenv("SOLAR_QUARTZ_USER");
            break;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SolarQuartzSink()).logSolarQuartz(dataArray);
    }
}

class CWE117_P08_V2_SolarQuartzSink {
    public void logSolarQuartz(String[] dataArray) {
        String data = dataArray[2];
        Logger solarQuartzLogger = Logger.getLogger("solarQuartz.audit");
        solarQuartzLogger.info("Login attempt for user " + data);
    }
}

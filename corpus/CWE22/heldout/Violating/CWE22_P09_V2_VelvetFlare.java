import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P09_V2_VelvetFlare {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    static class Container {
        public String containerOne;
    }

    public void openVelvetFlare() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("VELVET_FLARE_PATH");
        } else {
            data = null;
        }
        Container dataContainer = new Container();
        dataContainer.containerOne = data;
        (new CWE22_P09_V2_VelvetFlareSink()).readVelvetFlare(dataContainer);
    }
}

class CWE22_P09_V2_VelvetFlareSink {
    public void readVelvetFlare(CWE22_P09_V2_VelvetFlare.Container dataContainer) {
        String data = dataContainer.containerOne;
        String velvetFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetFlareFile = new File(velvetFlareRoot + data);
            FileInputStream velvetFlareStream = null;
            InputStreamReader velvetFlareStreamReader = null;
            BufferedReader velvetFlareReader = null;
            if (velvetFlareFile.exists() && velvetFlareFile.isFile()) {
                try {
                    velvetFlareStream = new FileInputStream(velvetFlareFile);
                    velvetFlareStreamReader = new InputStreamReader(velvetFlareStream, "UTF-8");
                    velvetFlareReader = new BufferedReader(velvetFlareStreamReader);
                    System.out.println(velvetFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P09_V2_VelvetFlareSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetFlareReader != null) {
                            velvetFlareReader.close();
                        }
                        if (velvetFlareStreamReader != null) {
                            velvetFlareStreamReader.close();
                        }
                        if (velvetFlareStream != null) {
                            velvetFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P09_V2_VelvetFlareSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

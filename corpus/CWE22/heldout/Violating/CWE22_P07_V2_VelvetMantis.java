import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_VelvetMantis {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void openVelvetMantis() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = (new CWE22_P07_V2_VelvetMantisSource()).locateVelvetMantis();
        } else {
            data = null;
        }
        String velvetMantisRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetMantisFile = new File(velvetMantisRoot + data);
            FileInputStream velvetMantisStream = null;
            InputStreamReader velvetMantisStreamReader = null;
            BufferedReader velvetMantisReader = null;
            if (velvetMantisFile.exists() && velvetMantisFile.isFile()) {
                try {
                    velvetMantisStream = new FileInputStream(velvetMantisFile);
                    velvetMantisStreamReader = new InputStreamReader(velvetMantisStream, "UTF-8");
                    velvetMantisReader = new BufferedReader(velvetMantisStreamReader);
                    System.out.println(velvetMantisReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_VelvetMantis").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetMantisReader != null) {
                            velvetMantisReader.close();
                        }
                        if (velvetMantisStreamReader != null) {
                            velvetMantisStreamReader.close();
                        }
                        if (velvetMantisStream != null) {
                            velvetMantisStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_VelvetMantis").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_VelvetMantisSource {
    public String locateVelvetMantis() {
        String data;
        data = System.getenv("VELVET_MANTIS_PATH");
        return data;
    }
}

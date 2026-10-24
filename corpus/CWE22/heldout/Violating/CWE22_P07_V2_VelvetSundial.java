import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V2_VelvetSundial {
    private static boolean privateReturnsTrue() { return true; }

    public void openVelvetSundial() {
        String data;
        if (privateReturnsTrue()) {
            data = (new CWE22_P07_V2_VelvetSundialSource()).locateVelvetSundial();
        } else {
            data = null;
        }
        String velvetSundialRoot = "/home/user/uploads/";
        if (data != null) {
            File velvetSundialFile = new File(velvetSundialRoot + data);
            FileInputStream velvetSundialStream = null;
            InputStreamReader velvetSundialStreamReader = null;
            BufferedReader velvetSundialReader = null;
            if (velvetSundialFile.exists() && velvetSundialFile.isFile()) {
                try {
                    velvetSundialStream = new FileInputStream(velvetSundialFile);
                    velvetSundialStreamReader = new InputStreamReader(velvetSundialStream, "UTF-8");
                    velvetSundialReader = new BufferedReader(velvetSundialStreamReader);
                    System.out.println(velvetSundialReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V2_VelvetSundial").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (velvetSundialReader != null) {
                            velvetSundialReader.close();
                        }
                        if (velvetSundialStreamReader != null) {
                            velvetSundialStreamReader.close();
                        }
                        if (velvetSundialStream != null) {
                            velvetSundialStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V2_VelvetSundial").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V2_VelvetSundialSource {
    public String locateVelvetSundial() {
        String data;
        data = System.getenv("VELVET_SUNDIAL_PATH");
        return data;
    }
}

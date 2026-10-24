import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V2_CrimsonOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void openCrimsonOrbit() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_ORBIT_PATH");
        } else {
            data = null;
        }
        String crimsonOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonOrbitFile = new File(crimsonOrbitRoot + data);
            FileInputStream crimsonOrbitStream = null;
            InputStreamReader crimsonOrbitStreamReader = null;
            BufferedReader crimsonOrbitReader = null;
            if (crimsonOrbitFile.exists() && crimsonOrbitFile.isFile()) {
                try {
                    crimsonOrbitStream = new FileInputStream(crimsonOrbitFile);
                    crimsonOrbitStreamReader = new InputStreamReader(crimsonOrbitStream, "UTF-8");
                    crimsonOrbitReader = new BufferedReader(crimsonOrbitStreamReader);
                    System.out.println(crimsonOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V2_CrimsonOrbit").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonOrbitReader != null) {
                            crimsonOrbitReader.close();
                        }
                        if (crimsonOrbitStreamReader != null) {
                            crimsonOrbitStreamReader.close();
                        }
                        if (crimsonOrbitStream != null) {
                            crimsonOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V2_CrimsonOrbit").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

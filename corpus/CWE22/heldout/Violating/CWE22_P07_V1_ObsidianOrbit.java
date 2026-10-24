import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V1_ObsidianOrbit {

    public void openObsidianOrbit() {
        String data;
        data = (new CWE22_P07_V1_ObsidianOrbitSource()).locateObsidianOrbit();
        String obsidianOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File obsidianOrbitFile = new File(obsidianOrbitRoot + data);
            FileInputStream obsidianOrbitStream = null;
            InputStreamReader obsidianOrbitStreamReader = null;
            BufferedReader obsidianOrbitReader = null;
            if (obsidianOrbitFile.exists() && obsidianOrbitFile.isFile()) {
                try {
                    obsidianOrbitStream = new FileInputStream(obsidianOrbitFile);
                    obsidianOrbitStreamReader = new InputStreamReader(obsidianOrbitStream, "UTF-8");
                    obsidianOrbitReader = new BufferedReader(obsidianOrbitStreamReader);
                    System.out.println(obsidianOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V1_ObsidianOrbit").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (obsidianOrbitReader != null) {
                            obsidianOrbitReader.close();
                        }
                        if (obsidianOrbitStreamReader != null) {
                            obsidianOrbitStreamReader.close();
                        }
                        if (obsidianOrbitStream != null) {
                            obsidianOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V1_ObsidianOrbit").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V1_ObsidianOrbitSource {
    public String locateObsidianOrbit() {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_PATH");
        return data;
    }
}

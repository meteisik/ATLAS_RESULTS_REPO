import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V2_ObsidianOrbit {
    private String obsidianOrbitData;

    private void readObsidianOrbit() {
        String data = obsidianOrbitData;
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
                    Logger.getLogger("CWE22_P05_V2_ObsidianOrbit").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P05_V2_ObsidianOrbit").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openObsidianOrbit() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("OBSIDIAN_ORBIT_PATH");
            break;
        default:
            data = null;
            break;
        }
        obsidianOrbitData = data;
        readObsidianOrbit();
    }
}

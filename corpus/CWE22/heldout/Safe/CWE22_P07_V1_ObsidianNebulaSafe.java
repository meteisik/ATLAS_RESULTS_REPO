import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V1_ObsidianNebulaSafe {

    public void openObsidianNebula() {
        String data;
        data = (new CWE22_P07_V1_ObsidianNebulaSafeSource()).locateObsidianNebula();
        String obsidianNebulaRoot = "/home/user/uploads/";
        if (data != null) {
            File obsidianNebulaFile = new File(obsidianNebulaRoot + data);
            FileInputStream obsidianNebulaStream = null;
            InputStreamReader obsidianNebulaStreamReader = null;
            BufferedReader obsidianNebulaReader = null;
            if (obsidianNebulaFile.exists() && obsidianNebulaFile.isFile()) {
                try {
                    obsidianNebulaStream = new FileInputStream(obsidianNebulaFile);
                    obsidianNebulaStreamReader = new InputStreamReader(obsidianNebulaStream, "UTF-8");
                    obsidianNebulaReader = new BufferedReader(obsidianNebulaStreamReader);
                    System.out.println(obsidianNebulaReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V1_ObsidianNebulaSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (obsidianNebulaReader != null) {
                            obsidianNebulaReader.close();
                        }
                        if (obsidianNebulaStreamReader != null) {
                            obsidianNebulaStreamReader.close();
                        }
                        if (obsidianNebulaStream != null) {
                            obsidianNebulaStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V1_ObsidianNebulaSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V1_ObsidianNebulaSafeSource {
    public String locateObsidianNebula() {
        String data;
        data = "foo";
        return data;
    }
}

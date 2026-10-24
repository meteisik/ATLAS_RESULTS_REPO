import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P07_V1_ObsidianHelixSafe {

    public void openObsidianHelix() {
        String data;
        data = (new CWE22_P07_V1_ObsidianHelixSafeSource()).locateObsidianHelix();
        String obsidianHelixRoot = "/home/user/uploads/";
        if (data != null) {
            File obsidianHelixFile = new File(obsidianHelixRoot + data);
            FileInputStream obsidianHelixStream = null;
            InputStreamReader obsidianHelixStreamReader = null;
            BufferedReader obsidianHelixReader = null;
            if (obsidianHelixFile.exists() && obsidianHelixFile.isFile()) {
                try {
                    obsidianHelixStream = new FileInputStream(obsidianHelixFile);
                    obsidianHelixStreamReader = new InputStreamReader(obsidianHelixStream, "UTF-8");
                    obsidianHelixReader = new BufferedReader(obsidianHelixStreamReader);
                    System.out.println(obsidianHelixReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P07_V1_ObsidianHelixSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (obsidianHelixReader != null) {
                            obsidianHelixReader.close();
                        }
                        if (obsidianHelixStreamReader != null) {
                            obsidianHelixStreamReader.close();
                        }
                        if (obsidianHelixStream != null) {
                            obsidianHelixStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P07_V1_ObsidianHelixSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

class CWE22_P07_V1_ObsidianHelixSafeSource {
    public String locateObsidianHelix() {
        String data;
        data = "foo";
        return data;
    }
}

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V2_ObsidianHelixSafe {
    private static int privateFive = 5;

    private String locateObsidianHelix() {
        String data;
        if (privateFive == 5) {
            data = "foo";
        } else {
            data = null;
        }
        return data;
    }

    public void openObsidianHelix() {
        String data = locateObsidianHelix();
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
                    Logger.getLogger("CWE22_P04_V2_ObsidianHelixSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P04_V2_ObsidianHelixSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}

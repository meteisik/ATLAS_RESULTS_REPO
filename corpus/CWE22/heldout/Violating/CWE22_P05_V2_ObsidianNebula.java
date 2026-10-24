import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V2_ObsidianNebula {
    private String obsidianNebulaData;
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void readObsidianNebula() {
        String data = obsidianNebulaData;
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
                    Logger.getLogger("CWE22_P05_V2_ObsidianNebula").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                        Logger.getLogger("CWE22_P05_V2_ObsidianNebula").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openObsidianNebula() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("OBSIDIAN_NEBULA_PATH");
        } else {
            data = null;
        }
        obsidianNebulaData = data;
        readObsidianNebula();
    }
}

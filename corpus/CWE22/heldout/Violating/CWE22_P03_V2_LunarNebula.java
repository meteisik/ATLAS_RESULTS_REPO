import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V2_LunarNebula {

    private void readLunarNebula(String data) {
        String lunarNebulaRoot = "/home/user/uploads/";
        if (data != null) {
            File lunarNebulaFile = new File(lunarNebulaRoot + data);
            FileInputStream lunarNebulaStream = null;
            InputStreamReader lunarNebulaStreamReader = null;
            BufferedReader lunarNebulaReader = null;
            if (lunarNebulaFile.exists() && lunarNebulaFile.isFile()) {
                try {
                    lunarNebulaStream = new FileInputStream(lunarNebulaFile);
                    lunarNebulaStreamReader = new InputStreamReader(lunarNebulaStream, "UTF-8");
                    lunarNebulaReader = new BufferedReader(lunarNebulaStreamReader);
                    System.out.println(lunarNebulaReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V2_LunarNebula").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (lunarNebulaReader != null) {
                            lunarNebulaReader.close();
                        }
                        if (lunarNebulaStreamReader != null) {
                            lunarNebulaStreamReader.close();
                        }
                        if (lunarNebulaStream != null) {
                            lunarNebulaStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V2_LunarNebula").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openLunarNebula() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("LUNAR_NEBULA_PATH");
            break;
        default:
            data = null;
            break;
        }
        readLunarNebula(data);
    }
}

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P04_V2_ObsidianBeacon {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String loadObsidianBeacon() {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("OBSIDIAN_BEACON_FILTER");
        } else {
            data = null;
        }
        return data;
    }

    public void runObsidianBeacon() throws SQLException {
        String data = loadObsidianBeacon();
        Connection obsidianBeaconConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianBeacon");
        Statement obsidianBeaconStatement = null;
        ResultSet obsidianBeaconRows = null;
        try {
            obsidianBeaconStatement = obsidianBeaconConnection.createStatement();
            obsidianBeaconRows = obsidianBeaconStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianBeaconRows.getRow());
        } finally {
            if (obsidianBeaconRows != null) {
                obsidianBeaconRows.close();
            }
            if (obsidianBeaconStatement != null) {
                obsidianBeaconStatement.close();
            }
            obsidianBeaconConnection.close();
        }
    }
}

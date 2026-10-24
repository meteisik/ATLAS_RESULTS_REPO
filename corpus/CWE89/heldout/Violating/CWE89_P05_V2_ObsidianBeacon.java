import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P05_V2_ObsidianBeacon {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private String obsidianBeaconData;

    private void queryObsidianBeacon() throws SQLException {
        String data = obsidianBeaconData;
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

    public void runObsidianBeacon() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_BEACON_FILTER");
        } else {
            data = null;
        }
        obsidianBeaconData = data;
        queryObsidianBeacon();
    }
}

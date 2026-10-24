import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_ObsidianBeacon {

    public void runObsidianBeacon() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_ObsidianBeaconSource()).loadObsidianBeacon();
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

class CWE89_P07_V1_ObsidianBeaconSource {
    public String loadObsidianBeacon() {
        String data;
        data = System.getenv("OBSIDIAN_BEACON_FILTER");
        return data;
    }
}

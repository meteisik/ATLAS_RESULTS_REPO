import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_ObsidianHelix {

    public void runObsidianHelix() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_ObsidianHelixSource()).loadObsidianHelix();
        Connection obsidianHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHelix");
        Statement obsidianHelixStatement = null;
        ResultSet obsidianHelixRows = null;
        try {
            obsidianHelixStatement = obsidianHelixConnection.createStatement();
            obsidianHelixRows = obsidianHelixStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianHelixRows.getRow());
        } finally {
            if (obsidianHelixRows != null) {
                obsidianHelixRows.close();
            }
            if (obsidianHelixStatement != null) {
                obsidianHelixStatement.close();
            }
            obsidianHelixConnection.close();
        }
    }
}

class CWE89_P07_V1_ObsidianHelixSource {
    public String loadObsidianHelix() {
        String data;
        data = System.getenv("OBSIDIAN_HELIX_FILTER");
        return data;
    }
}

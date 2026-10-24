import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_ObsidianRaven {

    public void runObsidianRaven() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_ObsidianRavenSource()).loadObsidianRaven();
        Connection obsidianRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianRaven");
        Statement obsidianRavenStatement = null;
        ResultSet obsidianRavenRows = null;
        try {
            obsidianRavenStatement = obsidianRavenConnection.createStatement();
            obsidianRavenRows = obsidianRavenStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianRavenRows.getRow());
        } finally {
            if (obsidianRavenRows != null) {
                obsidianRavenRows.close();
            }
            if (obsidianRavenStatement != null) {
                obsidianRavenStatement.close();
            }
            obsidianRavenConnection.close();
        }
    }
}

class CWE89_P07_V1_ObsidianRavenSource {
    public String loadObsidianRaven() {
        String data;
        data = System.getenv("OBSIDIAN_RAVEN_FILTER");
        return data;
    }
}

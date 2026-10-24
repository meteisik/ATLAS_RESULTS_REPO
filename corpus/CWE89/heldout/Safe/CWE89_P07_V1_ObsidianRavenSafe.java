import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P07_V1_ObsidianRavenSafe {

    public void runObsidianRaven() throws SQLException {
        String data;
        data = (new CWE89_P07_V1_ObsidianRavenSafeSource()).loadObsidianRaven();
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

class CWE89_P07_V1_ObsidianRavenSafeSource {
    public String loadObsidianRaven() {
        String data;
        data = "foo";
        return data;
    }
}

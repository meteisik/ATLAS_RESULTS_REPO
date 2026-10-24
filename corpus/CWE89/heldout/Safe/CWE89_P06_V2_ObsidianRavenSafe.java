import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P06_V2_ObsidianRavenSafe {

    public void runObsidianRaven() throws SQLException {
        String data;
        if (true) {
            data = "foo";
        } else {
            data = null;
        }
        (new CWE89_P06_V2_ObsidianRavenSafeSink()).queryObsidianRaven(data);
    }
}

class CWE89_P06_V2_ObsidianRavenSafeSink {
    public void queryObsidianRaven(String data) throws SQLException {
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

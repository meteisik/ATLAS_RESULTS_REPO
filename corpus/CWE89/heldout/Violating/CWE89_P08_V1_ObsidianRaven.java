import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_ObsidianRaven {

    public void runObsidianRaven() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_RAVEN_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_ObsidianRavenSink()).queryObsidianRaven(dataArray);
    }
}

class CWE89_P08_V1_ObsidianRavenSink {
    public void queryObsidianRaven(String[] dataArray) throws SQLException {
        String data = dataArray[2];
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

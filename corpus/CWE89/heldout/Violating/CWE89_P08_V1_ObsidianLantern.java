import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P08_V1_ObsidianLantern {

    public void runObsidianLantern() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_LANTERN_FILTER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE89_P08_V1_ObsidianLanternSink()).queryObsidianLantern(dataArray);
    }
}

class CWE89_P08_V1_ObsidianLanternSink {
    public void queryObsidianLantern(String[] dataArray) throws SQLException {
        String data = dataArray[2];
        Connection obsidianLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLantern");
        Statement obsidianLanternStatement = null;
        ResultSet obsidianLanternRows = null;
        try {
            obsidianLanternStatement = obsidianLanternConnection.createStatement();
            obsidianLanternRows = obsidianLanternStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(obsidianLanternRows.getRow());
        } finally {
            if (obsidianLanternRows != null) {
                obsidianLanternRows.close();
            }
            if (obsidianLanternStatement != null) {
                obsidianLanternStatement.close();
            }
            obsidianLanternConnection.close();
        }
    }
}
